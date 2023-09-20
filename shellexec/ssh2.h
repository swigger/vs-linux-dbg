#pragma once

struct SSH2Host
{
    std::string hostname;
    int port;
    string fingerprint;
    string username;
    string authenticationMethod;
    string privateFileName;
    string passphrase;
};
