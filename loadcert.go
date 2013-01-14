package main
import (
        "os"
        "fmt"
        "crypto/tls"
        "crypto/x509"
        "encoding/asn1"
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

func tryASN1UnmarshalToX509(crtFile string) {
        fmt.Println(">> tryASN1UnmarshalToX509",crtFile)
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
        var cert x509.Certificate
        rest, err := asn1.Unmarshal(block.Bytes, &cert)
        if err != nil {
                fmt.Println("err in asn1.Unmarshal",err)
        } else {
                fmt.Println("<< Success!")
        }
        if len(rest) > 0 {
                fmt.Println("rest from asn1.Unmarshal",rest)
        }
}

func tryASN1UnmarshalToTLS(crtFile string) {
        fmt.Println(">> tryASN1UnmarshalToTLS",crtFile)
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
        var cert tls.Certificate
        rest, err := asn1.Unmarshal(block.Bytes, &cert)
        if err != nil {
                fmt.Println("err in asn1.Unmarshal",err)
        } else {
                fmt.Println("<< Success!")
        }
        if len(rest) > 0 {
                fmt.Println("rest from asn1.Unmarshal",rest)
        }
}

func main() {
        tryTLSParse("client.crt", "client.key");
        tryTLSParse("client.clientAuth.crt", "client.key");
        tryX509Parse("client.crt");
        tryX509Parse("client.clientAuth.crt");
        tryASN1UnmarshalToX509("client.crt");
        tryASN1UnmarshalToX509("client.clientAuth.crt");
        tryASN1UnmarshalToTLS("client.crt");
        tryASN1UnmarshalToTLS("client.clientAuth.crt");
}
