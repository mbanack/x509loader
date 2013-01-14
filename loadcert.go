package main
import (
        "os"
        "fmt"
        "crypto/tls"
        "crypto/x509"
        "encoding/pem"
        "io"
)

func tryX509Parse(crtFile string) {
        fmt.Println(">> tryX509Parse",crtFile)
        fi, err := os.Open(crtFile)
        if err != nil {
                panic("Error opening " + crtFile)
        }
        pemBytes := make([]byte, 1024)
        n, err := fi.Read(pemBytes)
        if n >= 1024 {
                panic("cert bigger than buffer")
        }
        if err != io.EOF && err != nil {
                fmt.Println(err)
                panic("non-EOF error in cert read")
        }

        block, pemrest := pem.Decode(pemBytes[:n])
        if len(pemrest) > 0 {
                fmt.Println("pem.Decode had trailing",pemrest)
        }
        _, err = x509.ParseCertificate(block.Bytes)
        if err != nil {
                fmt.Println(err)
        } else {
                fmt.Println("<< Success!")
        }
}

func tryTLSParse(crtFile string, keyFile string) {
        fmt.Println(">> tryTLSParse",crtFile,keyFile)
        _, err := tls.LoadX509KeyPair(crtFile, keyFile)
        if err != nil {
                fmt.Println(err)
        } else {
                fmt.Println("<< Success!")
        }
}

func main() {
        tryTLSParse("client.crt", "client.key");
        tryTLSParse("client.clientAuth.crt", "client.key");
        tryX509Parse("client.crt");
        tryX509Parse("client.clientAuth.crt");
}
