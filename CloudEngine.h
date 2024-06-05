//
// Created by Michael on 24-4-29.
//

#ifndef JBC_CLOUDENGINE_H
#define JBC_CLOUDENGINE_H


#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include <pugixml.hpp>

static const std::string API_KEY = "a7c30a1033f3351d685910312f5d4118bf2ad9deaedc9f77c6fb3666bca5d3df";
static const std::string PEM = "-----BEGIN CERTIFICATE-----\n"
                               "MIIH8jCCBtqgAwIBAgIRANMtGScobsvAvwWpnCuavVAwDQYJKoZIhvcNAQELBQAw\n"
                               "XDELMAkGA1UEBhMCQ04xGjAYBgNVBAoTEVdvVHJ1cyBDQSBMaW1pdGVkMTEwLwYD\n"
                               "VQQDDChXb1RydXMgRFYgU2VydmVyIENBICBbUnVuIGJ5IHRoZSBJc3N1ZXJdMB4X\n"
                               "DTI0MDUxMTAwMDAwMFoXDTI1MDYxMTIzNTk1OVowEzERMA8GA1UEAxMIZi4zNjAu\n"
                               "Y24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDT5qcQocYMBUd/tNWu\n"
                               "oikK9MMiSjZ/imzB1Af4PzvtkiMDwxicxzdHCQFkO3MklR96PG04S/20ekhXnnq1\n"
                               "y4/yqAT4l1r2Vjjr/8nmuEB/t+PHQP+yVVkzKJp1GHTNH0kupbUOUILG0yu4yRjk\n"
                               "k7ayilFDW4zhiFl4pFH0oxpHI0MubeNUktp/cdfA2cj7pWJeNbxI333P/YKtZ6SW\n"
                               "TXNT2R5Ob6WcJK0CM0bEbNSugDPCuFIDjg63JgwKhxQTKrCHaYN487NfmzUVlsPf\n"
                               "75Y8lkaxb1oL2fxN6w5hdtpWSth4cJmSs/z7VxQ72Ylhd6a3wjHOovtSSfzPWdhE\n"
                               "MVTxAgMBAAGjggT2MIIE8jAfBgNVHSMEGDAWgBSZmy32i/Cj24nUnvvldC9o0pBP\n"
                               "5DAdBgNVHQ4EFgQUmSfjvweKzPlXWh0mfaQkSfbB98wwDgYDVR0PAQH/BAQDAgWg\n"
                               "MAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMEkG\n"
                               "A1UdIARCMEAwNAYLKwYBBAGyMQECAhYwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9z\n"
                               "ZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQIBMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6\n"
                               "Ly9jcmwuY3Jsb2NzcC5jbi9Xb1RydXNEVlNlcnZlckNBXzIuY3JsMGwGCCsGAQUF\n"
                               "BwEBBGAwXjA4BggrBgEFBQcwAoYsaHR0cDovL2FpYS5jcmxvY3NwLmNuL1dvVHJ1\n"
                               "c0RWU2VydmVyQ0FfMi5jcnQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLmNybG9j\n"
                               "c3AuY24wggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB2AM8RVu7VLnyv84db2Wku\n"
                               "m+kacWdKsBfsrAHSW3fOzDsIAAABj2VRdNAAAAQDAEcwRQIgc8wqT3h6Yfpahhqv\n"
                               "OgdfGTd5ThsEYTy92/iQRveunOcCIQCb+EY8TqN4rzB4esU8uRhQv8nc3r4Rtql6\n"
                               "+G5BCFAhfwB2AKLjCuRF772tm3447Udnd1PXgluElNcrXhssxLlQpEfnAAABj2VR\n"
                               "dGwAAAQDAEcwRQIhANE9pwqHihb/Piki6bckQArOBXqEc4cTmPFWdNdJRHYIAiA4\n"
                               "ZEadnDq9OiaG8kkvl46lqQJ5PC7XQH+srITkmr3v9gB2AE51oydcmhDDOFts1N8/\n"
                               "Uusd8OCOG41pwLH6ZLFimjnfAAABj2VRdGsAAAQDAEcwRQIhAOMD1mF2P8eQfq1I\n"
                               "sGbCZlgEFUK0tz6+DMm9G+6VTGnKAiAhW1Od5nvnBNDxaHCgF3YiSHOnG+9wh58C\n"
                               "qbVlJUT8CTCCAfcGA1UdEQSCAe4wggHqgghmLjM2MC5jboITKi5jbG91ZC4zNjBz\n"
                               "YWZlLmNvbYIKKi5mLjM2MC5jboILKi5mLjM2MC5uZXSCFCoubXZjb25mLjUwdW5p\n"
                               "b24uY29tghcqLm12ZC5jbG91ZC4zNjBzYWZlLmNvbYIOKi5tdmQuZi4zNjAuY26C\n"
                               "FioudmQuY2xvdWQuMzYwc2FmZS5jb22CDSoudmQuZi4zNjAuY26CEmIucHJlLnZk\n"
                               "LmYuMzYwLm5ldIIQYi50Y29uZi5mLjM2MC5jboIRYi50Y29uZjIuZi4zNjAuY26C\n"
                               "DmIudmQuZi4zNjAubmV0ghFjbG91ZC4zNjBzYWZlLmNvbYIJZi4zNjAubmV0ghJt\n"
                               "dmNvbmYuNTB1bmlvbi5jb22CFW12ZC5jbG91ZC4zNjBzYWZlLmNvbYIMbXZkLmYu\n"
                               "MzYwLmNughxvcGVuLm1zY2FuLmNsb3VkLjM2MHNhZmUuY29tghNvcGVuLm1zY2Fu\n"
                               "LmYuMzYwLmNughtvcGVuLnF1cmwuY2xvdWQuMzYwc2FmZS5jb22CEm9wZW4ucXVy\n"
                               "bC5mLjM2MC5jboIRcy5tdmNvbmYuZi4zNjAuY26CEHMudmNvbmYuZi4zNjAuY26C\n"
                               "FHZkLmNsb3VkLjM2MHNhZmUuY29tggt2ZC5mLjM2MC5jbjANBgkqhkiG9w0BAQsF\n"
                               "AAOCAQEAjuIA6e3n7lAY6c5LHQDrvubzvwXE1BB5suSDuuYlKMJ5GSl8+okxaCDs\n"
                               "Xde3UZ0u5LJocOsu1uGFdyu8LozTAWRyWxLVf5MK5xt9wDCBOXgp6O/BOv0TJVsH\n"
                               "Bgyrqsv86RcRO7qz5rRGhK963dRTmvCAT/ZIR/3XUhnVTRcbu1Gvt6XYOQ87iI4Z\n"
                               "yce8P0laYoupT6MVNxik1ITqmuQahrHwDZEu/o/28s10sbo26Rpq/eEsi+fWIQAX\n"
                               "kszs4Pn/M3lFVapeobwTjWNczKDi15JLvFS47Iac4IeV59KbLDg5+IcEce/+0tyo\n"
                               "EeZt9OvhFgTtpOgR6+9O/nYsq9IjNg==\n"
                               "-----END CERTIFICATE-----\n"
                               "-----BEGIN CERTIFICATE-----\n"
                               "MIIF4jCCA8qgAwIBAgIRANVuJGyU7WOrsUbvwZa2T7AwDQYJKoZIhvcNAQEMBQAw\n"
                               "gYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtK\n"
                               "ZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYD\n"
                               "VQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTIw\n"
                               "MDEwODAwMDAwMFoXDTMwMDEwNzIzNTk1OVowXDELMAkGA1UEBhMCQ04xGjAYBgNV\n"
                               "BAoTEVdvVHJ1cyBDQSBMaW1pdGVkMTEwLwYDVQQDDChXb1RydXMgRFYgU2VydmVy\n"
                               "IENBICBbUnVuIGJ5IHRoZSBJc3N1ZXJdMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
                               "MIIBCgKCAQEA7IE0rmVTVdRdNOzK1jsR/VppyukZ/XbQgakJHOhg6XGDsiHe/l5B\n"
                               "3PxyXw18jEdN+7YxP0qsGz+HlQbsQh6XlwIyjpz/2gFMiqa7y1v+dHOgj6xNOF5a\n"
                               "oaPm/Qhb0N+JYQidgaC+1Zp6W+YeC736rzCMr9vL1Usa3QLzRoQEo0DzbG4sPeP1\n"
                               "US0Ia/i8o6szArH+DAcvrzCZ2kkpTScQ9QfOsvkMBP1W2otICdKUyZHaBc+ztTAd\n"
                               "ovSlOR+GPf29dYfGQkZAp0tffIRw/na3WB86WGZPpNFfo2QxxsHYoL3oSWKfSWTY\n"
                               "FgW22J8eA03TFHYowm/NqYuJ7GW553HppQIDAQABo4IBcDCCAWwwHwYDVR0jBBgw\n"
                               "FoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFJmbLfaL8KPbidSe++V0\n"
                               "L2jSkE/kMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud\n"
                               "JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAiBgNVHSAEGzAZMA0GCysGAQQBsjEB\n"
                               "AgIWMAgGBmeBDAECATBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0\n"
                               "cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmww\n"
                               "cQYIKwYBBQUHAQEEZTBjMDoGCCsGAQUFBzAChi5odHRwOi8vY3J0LnVzZXJ0cnVz\n"
                               "dC5jb20vVVNFUlRydXN0UlNBQUFBQ0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8v\n"
                               "b2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQB5t8v3uYzHa4EL\n"
                               "0rOb9g/YAmptUbILcBMKk1x188ucsGVPaG1DG9bpVamxbmCtFA1MlrA7iUC8SGop\n"
                               "KBnuWFsNKiC7jCbRoahT1/FSwFsSuDlDmOjr1MqDXE+or08UkXsJB57XxXxdVOPl\n"
                               "DcZHII4qHi1XKK4iurMqb+kbdpAWadyfidRRCGPopYCVYLLYhRJgpFGtfr6Gk8N0\n"
                               "j81jq/7QbN0dRSDzMNdadKTc7c3+i9fIrXj79lV5Wvva+OL7nh8MxQhG1Ekek7Rv\n"
                               "en++jSZvaEhCrMsSedFTA/aIy7oJg85tfglF2ybK61HsobjYzdDNICKJlIm4chlA\n"
                               "XIDDqw2mw0Kz2snrkp9dpvMBqahF/Uy1kHzPcrq1/w5OqZWAuDKxZ68PuZ/ME2hI\n"
                               "YbIDG9dWT6Y7eqtjQ2TmAQbOqdAG2LeikPMl2DMrPEa4lcKJzsFbHfHAW3hVgPSQ\n"
                               "hRfS4TtbNnxijbsp8GguMHxP2R7dpAAYybwfZdXP7WYAnwEr1mzIf0Y3J0m7GDyX\n"
                               "JhaflN3G2wIm2HzRd39NvnDRmFEraqui/YYO9ym0pwq1d0S+bGG6876QCto0u3Cg\n"
                               "ItFh3Za2ZeIY+g5mWrejSaDs9LT7eu44iCyebfgekdMRqFeCuGAsJdsun3LOHHJo\n"
                               "tCVPRjyFg9NDeJeMa4Z8QuXAXLd9cw==\n"
                               "-----END CERTIFICATE-----\n"
                               "-----BEGIN CERTIFICATE-----\n"
                               "MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCB\n"
                               "iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl\n"
                               "cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV\n"
                               "BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAw\n"
                               "MjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV\n"
                               "BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU\n"
                               "aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy\n"
                               "dGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\n"
                               "AoICAQCAEmUXNg7D2wiz0KxXDXbtzSfTTK1Qg2HiqiBNCS1kCdzOiZ/MPans9s/B\n"
                               "3PHTsdZ7NygRK0faOca8Ohm0X6a9fZ2jY0K2dvKpOyuR+OJv0OwWIJAJPuLodMkY\n"
                               "tJHUYmTbf6MG8YgYapAiPLz+E/CHFHv25B+O1ORRxhFnRghRy4YUVD+8M/5+bJz/\n"
                               "Fp0YvVGONaanZshyZ9shZrHUm3gDwFA66Mzw3LyeTP6vBZY1H1dat//O+T23LLb2\n"
                               "VN3I5xI6Ta5MirdcmrS3ID3KfyI0rn47aGYBROcBTkZTmzNg95S+UzeQc0PzMsNT\n"
                               "79uq/nROacdrjGCT3sTHDN/hMq7MkztReJVni+49Vv4M0GkPGw/zJSZrM233bkf6\n"
                               "c0Plfg6lZrEpfDKEY1WJxA3Bk1QwGROs0303p+tdOmw1XNtB1xLaqUkL39iAigmT\n"
                               "Yo61Zs8liM2EuLE/pDkP2QKe6xJMlXzzawWpXhaDzLhn4ugTncxbgtNMs+1b/97l\n"
                               "c6wjOy0AvzVVdAlJ2ElYGn+SNuZRkg7zJn0cTRe8yexDJtC/QV9AqURE9JnnV4ee\n"
                               "UB9XVKg+/XRjL7FQZQnmWEIuQxpMtPAlR1n6BB6T1CZGSlCBst6+eLf8ZxXhyVeE\n"
                               "Hg9j1uliutZfVS7qXMYoCAQlObgOK6nyTJccBz8NUvXt7y+CDwIDAQABo0IwQDAd\n"
                               "BgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgEGMA8G\n"
                               "A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAFzUfA3P9wF9QZllDHPF\n"
                               "Up/L+M+ZBn8b2kMVn54CVVeWFPFSPCeHlCjtHzoBN6J2/FNQwISbxmtOuowhT6KO\n"
                               "VWKR82kV2LyI48SqC/3vqOlLVSoGIG1VeCkZ7l8wXEskEVX/JJpuXior7gtNn3/3\n"
                               "ATiUFJVDBwn7YKnuHKsSjKCaXqeYalltiz8I+8jRRa8YFWSQEg9zKC7F4iRO/Fjs\n"
                               "8PRF/iKz6y+O0tlFYQXBl2+odnKPi4w2r78NBc5xjeambx9spnFixdjQg3IM8WcR\n"
                               "iQycE0xyNN+81XHfqnHd4blsjDwSXWXavVcStkNr/+XeTWYRUc+ZruwXtuhxkYze\n"
                               "Sf7dNXGiFSeUHM9h4ya7b6NnJSFd5t0dCy5oGzuCr+yDZ4XUmFF0sbmZgIn/f3gZ\n"
                               "XHlKYC6SQK5MNyosycdiyA5d9zZbyuAlJQG03RoHnHcAP9Dc1ew91Pq7P8yF1m9/\n"
                               "qS3fuQL39ZeatTXaw2ewh0qpKJ4jjv9cJ2vhsE/zB+4ALtRZh8tSQZXq9EfX7mRB\n"
                               "VXyNWQKV3WKdwrnuWih0hKWbt5DHDAff9Yk2dDLWKMGwsAvgnEzDHNb842m1R0aB\n"
                               "L6KCq9NjRHDEjf8tM7qtj3u1cIiuPhnPQCjY/MiQu12ZIvVS5ljFH4gxQ+6IHdfG\n"
                               "jjxDah2nGN59PRbxYvnKkKj9\n"
                               "-----END CERTIFICATE-----";

class CloudEngine {
public:
    struct VT_FileReport {
        int httpStatus;
        int attribute;  //0:safe    1:undetected    2:malware
        std::string ESET;
        std::string Kaspersky;
        std::string threat_label;
        std::string malicious;  //暂时不需要用到
    };
    struct QH_FileReport{
        int httpStatus;
        int attribute;  //0:safe    1:undetected    2:malware
        std::string threat_label;
        int ages;
        int pop;
    };

    static VT_FileReport VT_GetFileReport(const std::string &fileHash);

    static QH_FileReport QH_GetFileReport(const std::string &fileHash);
};


#endif //JBC_CLOUDENGINE_H
