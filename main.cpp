#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <cstdint>
#include <thread>
#include <chrono>
#include <vector>
#include <string>

#include "argparse.h"
#include "mongoose.h"
#include "api.h"
#include "randombytes.h"

const std::vector<std::string> MG_LABELS = {"MG_EV_POLL",
                                            "MG_EV_ACCEPT",
                                            "MG_EV_CONNECT",
                                            "MG_EV_RECV",
                                            "MG_EV_SEND",
                                            "MG_EV_CLOSE",
                                            "MG_EV_TIMER"};

constexpr uint16_t CHALLENGE_SIZE = 32;

void rtrim(std::string& s, const std::string& delimiters = " \f\n\r\t\v" ) {
    s.erase( s.find_last_not_of( delimiters ) + 1 );
}

void ltrim(std::string& s,  const std::string& delimiters = " \f\n\r\t\v" ) {
    s.erase( 0, s.find_first_not_of( delimiters ) );
}

void trim(std::string& s, const std::string& delimiters = " \f\n\r\t\v" ) {
    s.erase( s.find_last_not_of( delimiters ) + 1 ).erase( 0, s.erase( s.find_last_not_of( delimiters ) + 1 ).find_first_not_of( delimiters ) );
}

std::string get_current_session() {
    constexpr size_t DATA_SIZE = 512;
    char data[DATA_SIZE];
    if(system("which loginctl") == 0 && system("which awk") == 0) {
        FILE* f = popen("loginctl list-sessions --no-legend | awk '{ print $1 }'","r");
        if(f==nullptr) goto os_err;
        char *line_p = fgets(data, DATA_SIZE, f);
        std::string s(line_p);
        trim(s);
        pclose(f);
        return s;
    }
    else goto os_err;

    os_err:
    throw std::runtime_error("The necessary binaries awk and/or loginctl are not present on this machine");
}

void unlock_session() {
    std::cout<<"Unlocking session..."<<std::endl;
    if(system(("loginctl unlock-session "+get_current_session()).c_str()))
        std::cerr<<"Unable to unlock session"<<std::endl;
}

int export_data(const std::string &k_filename,
                const std::vector<uint8_t> &k) {
    try {
        std::ofstream pks;
        pks.open(k_filename, std::ios::out | std::ios::binary);
        pks.write((const char*)&k[0], k.size());
        return 0;
    }
    catch(...) {
        std::cerr<<"Unable to export data"<<std::endl;
        return -1;
    }
}

std::vector<uint8_t> import_data(const std::string &k_filename) {
    FILE* f = fopen(k_filename.c_str(),"rb");
    if(f == nullptr) return {};
    fseek(f, 0L, SEEK_END);
    auto sz = ftell(f);
    size_t currentRead = 0;
    fseek(f, 0L, SEEK_SET);
    std::vector<uint8_t> k(sz,0);
    for(;;) {
        size_t readBytes = fread((&k[0])+currentRead,1024,1,f);
        if(readBytes <= 0) break;
        currentRead += readBytes;
    }
    fclose(f);
    return k;
}

constexpr size_t SIGNATURE_MAX_SIZE = SPX_BYTES;

struct grimaldo_user_data {
    uint8_t challenge[CHALLENGE_SIZE];
    uint8_t P[CHALLENGE_SIZE]; // client's postfix, for server will be populated on first client response
    uint8_t challenge_P[2*CHALLENGE_SIZE];
    size_t sigBytesReceivedSoFar;
    bool postfixReceived;
    uint8_t signedResponse[SIGNATURE_MAX_SIZE];
    sock_t sock_id;
};

static uint8_t* grimaldo_server_pubkey;
static uint8_t* grimaldo_client_privkey;

static void grimaldo_server_ev_handler(struct mg_connection *nc, int ev, void *unused) {
    struct mbuf *io = &(nc->recv_mbuf);
    auto* ud = (grimaldo_user_data *) nc->user_data;

    int verificationResult = -1;

    switch(ev) {
        case MG_EV_RECV:
            fwrite("=",1,1,stdout);
            // std::cout<<"RECEIVE EVENT"<<std::endl;
            /**
             * step #1:
             * receive from client:
             * - postfix P (256-bit randomness)
             * - signature of (challenge | P)
             */

            // TODO add first packet size >= CHALLENGE_SIZE check

            if(!ud->postfixReceived) {
                memcpy(ud->P,io->buf,CHALLENGE_SIZE);
                ud->sigBytesReceivedSoFar = io->len - CHALLENGE_SIZE;
                memcpy(ud->signedResponse,io->buf + CHALLENGE_SIZE,ud->sigBytesReceivedSoFar);
                ud->postfixReceived = true;
            }
            else {
                memcpy(ud->signedResponse + ud->sigBytesReceivedSoFar,io->buf,io->len);
                ud->sigBytesReceivedSoFar += io->len;
            }
            if(ud->sigBytesReceivedSoFar >= SIGNATURE_MAX_SIZE) {
                // here, we have already received the entire postfix+signature

                memcpy(ud->challenge_P,ud->challenge,CHALLENGE_SIZE);
                memcpy(ud->challenge_P+CHALLENGE_SIZE,ud->P,CHALLENGE_SIZE);

                // verify signature, then disconnect in any case (if signature verification succeeds, perform unlock command)
                verificationResult = crypto_sign_verify(ud->signedResponse, SIGNATURE_MAX_SIZE,
                                                        ud->challenge_P, 2*CHALLENGE_SIZE,
                                                        grimaldo_server_pubkey);
                std::cout<<"Verification "<<(verificationResult?"failed":"OK")<<std::endl;

                if(verificationResult == 0) {
                    unlock_session();
                }

                // TODO disconnect client
            }

            mbuf_remove(io, io->len);       // Discard message from recv buffer
            break;
        case MG_EV_ACCEPT:
            // client just connected (step #0), send challenge (256 bit random value)
            std::cerr<<"Accepted successfully, socket is "<<nc->sock<<std::endl;
            if(ud == nullptr) {
                ud = new grimaldo_user_data();
                ud->sock_id = nc->sock;
                nc->user_data = ud;
            }
            else {
                std::cerr<<"ud should be null on accept, exiting..."<<std::endl;
                _Exit(-1);
            }
            randombytes(ud->challenge,CHALLENGE_SIZE);
            mg_send(nc, ud->challenge, CHALLENGE_SIZE);
            break;
        case MG_EV_CLOSE:
            // FIXME temporary
            if(ud != nullptr) {
                auto sockId = ud->sock_id;
                delete ud;
                std::cerr<<"deallocated ud for socket "<<sockId<<" on close"<<std::endl;
            }
            else {
                std::cerr<<"WARNING: found ud null on close"<<std::endl;
            }
            break;
        default:
            if(MG_LABELS[ev] != "MG_EV_POLL")
                std::cout<<"Received event: "<<MG_LABELS[ev]<<" ("<<ev<<")"<<std::endl;
            break;
    }
}

int grimaldo_server(const std::string public_key_path = "pubk.pubk",
                     const std::string listen_address = "0.0.0.0",
                     const uint16_t listen_port = 11112) {
    auto&& imported_pk = import_data(public_key_path);
    if(imported_pk.empty()) {
        std::cerr<<"Unable to import key"<<std::endl;
        _Exit(-1);
    }
    grimaldo_server_pubkey = new uint8_t[imported_pk.size()];
    memcpy(grimaldo_server_pubkey,&imported_pk[0],imported_pk.size());

    std::cout<<"Running in server mode, listening on address "<<listen_address<<", port "<<listen_port<<", public key file: "<<public_key_path<<std::endl;
    struct mg_mgr mgr{};
    std::string joinedAddress = "tcp://" + listen_address + ":" + std::to_string(listen_port);
    const char* addr = joinedAddress.c_str(); // tcp://0.0.0.0:11112

    mg_mgr_init(&mgr, nullptr);
    mg_bind(&mgr, addr, grimaldo_server_ev_handler);

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);
    return 0;
}

static void grimaldo_client_ev_handler(struct mg_connection *nc, int ev, void *unused) {
    struct mbuf *io;
    auto* ud = (grimaldo_user_data *) nc->user_data;

    size_t signatureLength = SIGNATURE_MAX_SIZE;
    constexpr size_t msgSize = 2*CHALLENGE_SIZE;

    switch(ev) {
        case MG_EV_SEND:
            io = &(nc->send_mbuf);
            std::cout<<"Message actually sent, remaining bytes in the send buffer "<<io->len<<std::endl;
            if(io->len == 0) {
                std::cout<<"Send completed, exiting..."<<std::endl;
                _Exit(0);
            }
            break;
        case MG_EV_RECV:
            std::cout<<"RECEIVE EVENT"<<std::endl;
            // (step #0) server has sent challenge
            io = &(nc->recv_mbuf);
            if(io->len != CHALLENGE_SIZE) {
                std::cerr<<"Server sent packet with size "<<io->len<<", expected "<<CHALLENGE_SIZE<<std::endl;
                _Exit(-1);
            }
            memcpy(ud->challenge,io->buf,CHALLENGE_SIZE);

            // generate postfix
            randombytes(ud->P,CHALLENGE_SIZE);

            memcpy(ud->challenge_P,ud->challenge,CHALLENGE_SIZE);
            memcpy(ud->challenge_P+CHALLENGE_SIZE,ud->P,CHALLENGE_SIZE);

            // generate and send signature
            // api inconsistency here? signatureLength is required as pointer (dereferenced and assigned),
            // but sig must be preallocated
            crypto_sign_signature(ud->signedResponse,&signatureLength,ud->challenge_P,msgSize,grimaldo_client_privkey);

            mbuf_remove(io, io->len); // Discard message from recv buffer

            // send postfix
            mg_send(nc,ud->P,CHALLENGE_SIZE);
            // send signature
            mg_send(nc,ud->signedResponse,signatureLength);
            break;
        case MG_EV_CLOSE:
            std::cout<<"Server closed connection, exiting..."<<std::endl;
            _Exit(0);
            break;
        default:
            std::cout<<"Received event: "<<MG_LABELS[ev]<<" ("<<ev<<")"<<std::endl;
    }
}

int grimaldo_client(const std::string private_key_path = "prvk.prvk",
                     const std::string connect_address = "127.0.0.1",
                     const uint16_t connect_port = 11112) {
    auto&& imported_pk = import_data(private_key_path);
    if(imported_pk.empty()) {
        std::cerr<<"Unable to import key"<<std::endl;
        _Exit(-1);
    }
    grimaldo_client_privkey = new uint8_t[imported_pk.size()];
    memcpy(grimaldo_client_privkey,&imported_pk[0],imported_pk.size());

    struct mg_connect_opts connect_opts{};
    auto* ud = new grimaldo_user_data();
    connect_opts.user_data = ud;

    std::cout<<"Running in client mode, connecting to address "<<connect_address<<", port "<<connect_port<<", private key file: "<<private_key_path<<std::endl;
    struct mg_mgr mgr{};
    mg_mgr_init(&mgr, nullptr);
    std::string joinedAddress = "tcp://" + connect_address + ":" + std::to_string(connect_port);

//    auto* nc = mg_connect(&mgr, joinedAddress.c_str(), grimaldo_client_ev_handler);
    auto* nc = mg_connect_opt(&mgr, joinedAddress.c_str(), grimaldo_client_ev_handler, connect_opts);

    if(nc == nullptr) {
        std::cerr<<"Cannot create connection object"<<std::endl;
        return -1;
    }

    for(;;) {
        std::cout<<"Sleeping..."<<std::endl;
        mg_mgr_poll(&mgr, 1000);
//        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}

int gen_keypair(const std::string private_key_path = "prvk.prvk",
                const std::string public_key_path = "pubk.pubk") {
    std::vector<uint8_t> pk(SPX_PK_BYTES,0);
    std::vector<uint8_t> sk(SPX_SK_BYTES,0);

    if (crypto_sign_keypair(&pk[0], &sk[0]))
        goto kp_gen_error;

    if(export_data(public_key_path, pk)) goto kp_gen_error;
    if(export_data(private_key_path, sk)) goto kp_gen_error;
    return 0;

kp_gen_error:
    std::cerr<<"Keypair generation error"<<std::endl;
    return -1;
}

int print_usage(char* prog_name) {
    std::cout<<"Usage: "<<prog_name<<" client <--connect_address 127.0.0.1> <--connect_port 11112> <--private_key prvk.prvk>"<<std::endl;
    std::cout<<"OR"<<std::endl;
    std::cout<<"Usage: "<<prog_name<<" server <--listen_address 0.0.0.0> <--listen_port 11112> <--public_key pubk.pubk>"<<std::endl;
    std::cout<<"OR"<<std::endl;
    std::cout<<"Usage: "<<prog_name<<" gen <--private_key prvk.prvk> <--public_key pubk.pubk>"<<std::endl;
    std::cout<<"(all arguments except the exec mode - client,server,gen - are optional)"<<std::endl;

    return 0;
}

int custom_string_to_int(const std::string& s, int& result) {
    try {
        result = std::stoi(s);
        return 0;
    } catch (...) {
        return -1;
    }
}

int parse_client_args_and_run(int argc, char* argv[]) {
    ArgumentParser parser("Client argument parser");
    parser.add_argument("-a", "--connect_address", "the connect address, default 127.0.0.1", false);
    parser.add_argument("-p", "--connect_port", "the connect port, default 11112", false);
    parser.add_argument("-k", "--private_key", "the private key filename or path, default \"prvk.prvk\"", false);
    try {
        parser.parse(argc, argv);
    } catch (const ArgumentParser::ArgumentNotFound& ex) {
        std::cout << ex.what() << std::endl;
        return -1;
    }
    if (parser.is_help()) return -2;
    auto address = parser.get<std::string>("a");
    if(address.empty()) address = "127.0.0.1";
    auto port_str = parser.get<std::string>("p");
    int port;
    if(custom_string_to_int(port_str,port)) port = 11112;
    auto key = parser.get<std::string>("k");
    if(key.empty()) key = "prvk.prvk";

    return grimaldo_client(key,address,port);
}

int parse_server_args_and_run(int argc, char* argv[]) {
    ArgumentParser parser("Server argument parser");
    parser.add_argument("-a", "--listen_address", "the listen address, default 0.0.0.0", false);
    parser.add_argument("-p", "--listen_port", "the listen port, default 11112", false);
    parser.add_argument("-k", "--public_key", "the public key filename or path, default \"pubk.pubk\"", false);
    try {
        parser.parse(argc, argv);
    } catch (const ArgumentParser::ArgumentNotFound& ex) {
        std::cout << ex.what() << std::endl;
        return -1;
    }
    if (parser.is_help()) return -2;
    auto address = parser.get<std::string>("a");
    if(address.empty()) address = "0.0.0.0";
    auto port_str = parser.get<std::string>("p");
    int port;
    if(custom_string_to_int(port_str,port)) port = 11112;
    auto key = parser.get<std::string>("k");
    if(key.empty()) key = "pubk.pubk";

    return grimaldo_server(key,address,port);
}

int parse_gen_args_and_run(int argc, char* argv[]) {
    ArgumentParser parser("Server argument parser");
    parser.add_argument("-j", "--private_key", "the private key filename or path, default \"prvk.prvk\"", false);
    parser.add_argument("-k", "--public_key", "the public key filename or path, default \"pubk.pubk\"", false);
    try {
        parser.parse(argc, argv);
    } catch (const ArgumentParser::ArgumentNotFound& ex) {
        std::cout << ex.what() << std::endl;
        return -1;
    }
    if (parser.is_help()) return -2;
    auto private_key = parser.get<std::string>("j");
    if(private_key.empty()) private_key = "prvk.prvk";
    auto public_key = parser.get<std::string>("k");
    if(public_key.empty()) public_key = "pubk.pubk";

    return gen_keypair(private_key,public_key);
}

int main(int argc, char* argv[]) {
    if(argc < 2) return print_usage(argv[0]);
    std::string mode(argv[1]);
    if(mode=="client")
        return parse_client_args_and_run(argc,argv);
    else if(mode=="server")
        return parse_server_args_and_run(argc,argv);
    else if(mode=="gen")
        return parse_gen_args_and_run(argc,argv);
    else return print_usage(argv[0]);
}
