# NetProbe

NetProbe is a command-line utility designed to retrieve and analyze information about websites. It provides insights into various aspects of a website, including its IP address, geolocation data, SSL certificate details, and technology stack.

## Features

- **Website IP Address:** Discover the IP address associated with a given website.
- **Geolocation Data:** Retrieve information about the geographical location of the website server.
- **SSL Certificate Details:** Obtain details about the SSL certificate used by the website, including subject and issuer information.
- **Technology Stack Detection:** Detect the technology stack utilized by the website, such as web frameworks, content management systems, and JavaScript libraries.

## Installation

1. **Clone the Repository:**
```
git clone https://github.com/gryphonribz/NetProbe.git
```

2. **Navigate to the NetProbe Directory:**
```
cd NetProbe
```

3. **Compile the Program:**
```
make
```

4. **Run NetProbe:**
```
./NetProbe
```

## Usage

To use NetProbe, simply execute the binary and follow the on-screen instructions. You'll be prompted to enter the website link (without `http://` or `https://`). NetProbe will then gather and display the requested information.

## Example:
Enter the website link (without http:// or https://): example.com


## Dependencies

NetProbe relies on the following libraries:
- libcurl: For making HTTP requests.
- OpenSSL: For SSL certificate handling.
- json-c: For parsing JSON responses.
- Wappalyzer: For detecting the website's technology stack.

Ensure that these libraries are installed on your system before compiling and running NetProbe.

## Contributing

Contributions to NetProbe are welcome! If you find any bugs or have suggestions for improvements, please open an issue or submit a pull request on GitHub.

## License

NetProbe is licensed under the [GNU GPL V3](LICENSE).

