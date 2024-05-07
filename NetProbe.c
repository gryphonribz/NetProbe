#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <wappalyzer/wappalyzer.h>
#include <string>

// ASCII Art with Cyberpunk Theme
const char *ascii_art =
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m░\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m░\033[0m\033[38;5;208m░\033[0m\033[38;5;208m▒\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m░\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m░\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m░\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m░\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▒\033[0m\033[38;5;208m░\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\n"
    "\033[38;5;208m▒\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m█\033[0m\033[38;5;208m█\033[0m\033[38;5;208m▓\033[0m\033[38;5;208m▓\033[0m\n";

int main() {
    // Print the ASCII art
    printf("%s", ascii_art);


// Write callback for curl
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char **response_ptr = (char **)userp;
    *response_ptr = strndup(contents, realsize);
    return realsize;
}

// Function to get the IP address of a given URL
char* get_ip_address(char* url) {
    struct addrinfo hints, *res;
    char *ip_address = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(url, NULL, &hints, &res) != 0) {
        return NULL;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    ip_address = strdup(inet_ntoa(addr->sin_addr));

    freeaddrinfo(res);
    return ip_address;
}

// Function to get the geolocation information of an IP address
char* get_geolocation(char* ip) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;

    curl = curl_easy_init();
    if (curl) {
        char url[256];
        sprintf(url, "https://ipwhois.app/json/%s", ip);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            struct json_object *parsed_json;
            parsed_json = json_tokener_parse(response);
            // Extract geolocation data from the parsed JSON
            struct json_object *city, *country;
            if (json_object_object_get_ex(parsed_json, "city", &city) &&
                json_object_object_get_ex(parsed_json, "country", &country)) {
                char *result = malloc(256);
                sprintf(result, "City: %s, Country: %s", json_object_get_string(city), json_object_get_string(country));
                free(response);
                json_object_put(parsed_json);
                return result;
            }
            json_object_put(parsed_json);
        }
        free(response);
        curl_easy_cleanup(curl);
    }

    return strdup("Error getting geolocation data");
}

// Function to get SSL certificate information
char* get_ssl_certificate(char* url) {
    SSL_CTX *ctx;
    SSL *ssl;
    X509 *cert;
    char *cert_info = NULL;

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    if (!ctx) {
        return strdup("Unable to create SSL context");
    }

    // Establishing connection
    BIO *bio = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(bio, url);

    if (BIO_do_connect(bio) <= 0) {
        SSL_CTX_free(ctx);
        return strdup("Error connecting via SSL");
    }

    // Retrieving certificate
    ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);

    if (SSL_get_verify_result(SSL_get_SSL_CTX(ssl)) != X509_V_OK) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return strdup("Error verifying SSL certificate");
    }

    cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return strdup("Error retrieving SSL certificate");
    }

    char *subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    cert_info = malloc(strlen(subject) + strlen(issuer) + 50);
    sprintf(cert_info, "Subject: %s\nIssuer: %s", subject, issuer);

    X509_free(cert);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return cert_info;
}

// Function to detect the technology stack used by a website
char* get_technology_stack(char* url) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;

    curl = curl_easy_init();
    if (curl) {
        char full_url[256];
        sprintf(full_url, "http://%s", url);

        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            curl_easy_cleanup(curl);
            return strdup("Error detecting technology stack");
        }

        Wappalyzer wappalyzer;
        std::string response_str(response);
        json technologies = wappalyzer.analyze(response_str);

        curl_easy_cleanup(curl);
        return strdup(technologies.dump().c_str());
    }

    return strdup("CURL initialization failed");
}

// Main function
int main() {
    char url[256];
    printf("Enter the website link (without http:// or https://): ");
    scanf("%s", url);

    char *ip_address = get_ip_address(url);
    if (ip_address) {
        printf("Website IP Address: %s\n", ip_address);

        char *geo_info = get_geolocation(ip_address);
        printf("Geolocation Info: %s\n", geo_info);
        free(geo_info);

        char *ssl_info = get_ssl_certificate(url);
        printf("SSL Certificate Info: %s\n", ssl_info);
        free(ssl_info);

        char *tech_stack = get_technology_stack(url);
        printf("Technology Stack Used: %s\n", tech_stack);
        free(tech_stack);

        free(ip_address);
    } else {
        printf("Error resolving domain to IP address\n");
    }

    return 0;
}
