package com.aliyuncs.kms.secretsmanager.client.v2.utils;


import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

public interface PrivateCaUtils {

    String preEnvCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDbjCCAlYCCQDLj6fIuosmVDANBgkqhkiG9w0BAQsFADB0MQswCQYDVQQGEwJD\n" +
            "TjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmdaaG91MRAwDgYDVQQK\n" +
            "DAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xHDAaBgNVBAMME1ByaXZhdGUgS01T\n" +
            "IFJvb3QgQ0EwHhcNMjEwNzA4MDcwNTA1WhcNNDEwNzAzMDcwNTA1WjB+MQswCQYD\n" +
            "VQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmdaaG91MRAw\n" +
            "DgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xJjAkBgNVBAMMHVByaXZh\n" +
            "dGUgS01TIHByZS1zZ3AgU2Vjb25kIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
            "MIIBCgKCAQEAzqANlA7KDaPFJ49UvdY7hWNczCh3JnwCRygCA61W7fo/OW+aRA5r\n" +
            "jMqlHcNkk3ODvMmDlf/UUdpbLAN1uP/O7zNGnwhiP6EwhGdxEApZEfw7hzS3jEHs\n" +
            "tzIoQ/cDWO09b9V+S7P+Fn2HBh66HAL9Zf9DjqN6lRke92L17cu+fYcrVWe1Uqqm\n" +
            "nrXnAwEdbEAA0z7b02dDJuGN8w59brGPe4NcbVCroaqGyrmyK69iNENIk9HcrmPH\n" +
            "iUvUsTFL+lQQE52s36JSKn3vnZdAFkMOmkdrdmbXoT9zICYG6FD5M8mCZSzQrlFP\n" +
            "QMMnkjhfw/Gc2OwGwb2T5JxCoXeDyL48xwIDAQABMA0GCSqGSIb3DQEBCwUAA4IB\n" +
            "AQCAV2koOF/AZbCE8PQaipgNnJsfTTrU72b+zEi+bGNZqCw9G637C3zJmIH0xZgN\n" +
            "T/RzfNi+TITcz7xgYe3SAS7s3A60hJfBOCBipLXXOuCa0piTdycGk/RmxkwT5kZm\n" +
            "cK/YwMFnC/3xLAm/W9W835t5Rd5fGLMaHHnZdMffMHzg3X6WHJuKbuhVz/NBJciJ\n" +
            "jM0eifTWNV/saDUEbXdv/TlaH+gfk+mNc8pb7WktKWUvgtH8pUcRvQ5NzDzBmqQ/\n" +
            "8PSZpOMX6myxV0yn9+2VFbPsBCrg9QrGdM49iVdshx2Z0B8AGs5lRuA7i3MTuuik\n" +
            "O7fWJLGHDMzF6NCnjHVd2OuT\n" +
            "-----END CERTIFICATE-----";

    String hzCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4DCCAsigAwIBAgIJAINenTNhDtsXMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMjAyMjQwNjI4MDJaFw00MjAyMTkwNjI4MDJaMIGC\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKjAoBgNVBAMM\n" +
            "IVByaXZhdGUgS01TIGNuLWhhbmd6aG91IFNlY29uZCBDQTCCASIwDQYJKoZIhvcN\n" +
            "AQEBBQADggEPADCCAQoCggEBANI3BTw59Zoga5A9h1FCVb+9mZljuTTxqpm27aY5\n" +
            "teWdWBWpf+QhnA1jrIHXAFDkcL/X4nJZsuP5wc0OE3dzikLRi8Khjtbr4YXXDdGA\n" +
            "+6Pb4ojo72eTa9PF7oRNUgoN8CirtbmQ/rZNN5wYyxdJSfxkrl9v5c2D/+w5tkZF\n" +
            "0GA/CvACRcvcS1yrkGz4P/FudLiCkdVp6ZiRkheECBT8+Xypgyp5hBJpyJZ1Wl0/\n" +
            "Ng8BuOxr7QpsWWHem5Oy8BuKi4auJhTphpKw28xOPRtrsnmsaKPlW7O/ZIcdNlQq\n" +
            "pUqiQcdL/Xq6XnXXkZkJDJ31rbnPqUjKumW4fecA2yMQzekCAwEAAaNmMGQwHQYD\n" +
            "VR0OBBYEFIINFyJHHoaPbjoibVHwoXgM/Ka9MB8GA1UdIwQYMBaAFAVKzUR5/d6j\n" +
            "nYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG\n" +
            "MA0GCSqGSIb3DQEBCwUAA4IBAQAAU+9Mu3mVfnpG/jTumvtroWVc6yZOXvIpoIBm\n" +
            "LzHgQlYAWsPxZkfIS9hHaFgZ0e+rTWZDYAjfpChiw6krenThD6XCUI8pHkiIzg09\n" +
            "9C36oM+YWlSzUGikttWGgXhQhFYERM0EFIGdnLCzuYlMMrnbCh2ThWse+Wx9NE1b\n" +
            "JfhbX69WkhdNbHImXpSNng23Rt0Bl+hEVkj9ejqS0nGVfsOItqCxxJ17qHuGFPq4\n" +
            "FmiKQvv19ZuChay2yqr3/8t7uv+ZLLoYYMnJ3KifH4nMlxVUizoLKNHMPmXGgKX5\n" +
            "ldn72kPUZ8oXsRlKn5nQ7fHO3uTktZ5mZf20VZai0GlQdORN\n" +
            "-----END CERTIFICATE-----";

    String sgpCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4zCCAsugAwIBAgIJALAGEGJJrHm8MA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzEyMjAxMDEzMjdaFw00MzEyMTUxMDEzMjdaMIGF\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xLTArBgNVBAMM\n" +
            "JFByaXZhdGUgS01TIGFwLXNvdXRoZWFzdC0xIFNlY29uZCBDQTCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBAOS8SyiuxRx+oJMRAExiyTMlL+fNQBJWUkCI\n" +
            "RVhCUqBRmTW36RqJ/FxchgQ7UfSQpIweYMAURMr/gXWioNwVoUcdTKxD6jrtbiKK\n" +
            "vUo7Kh5JGKH3cwdQljo5My9PWB/d3DVu/zqmPIWmrZqvrNJsZfFKqfnsGhCH2O3P\n" +
            "ybd3cyh2jmsWr8j7lg9yc1Jv/Q/H5hHImDVBI30cvuz0qMEOAiLwkeyXn93klZ75\n" +
            "c8GngeuoskR0OpRcu3R5oMKCXY2zuBjhbaPeq3kEtBNOp1rlGQM5yQvZJL052ZDT\n" +
            "+DjcLv/T4xxvod5SesqteNyT2H77rbHgeaOzqa0iN5D/X07pjT8CAwEAAaNmMGQw\n" +
            "HQYDVR0OBBYEFHkKZPgVjBSFLuGtZnO4vdxgD9xSMB8GA1UdIwQYMBaAFAVKzUR5\n" +
            "/d6jnYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD\n" +
            "AgGGMA0GCSqGSIb3DQEBCwUAA4IBAQAz1KLfRIk9BGuagjWeXC+NolYJPQxwU/rI\n" +
            "rUcAq9VcyMOtjC6JfxpxzwIfNVtBTuvIt/dDKrGbECV+lvnFNbMdTIGyQWRhNac6\n" +
            "f+fWyC87tIRMu3/+qGKJq8NEfkiuL/ZDULCMGZ/M05pmklQ23wpHwMF5ti0q9iCn\n" +
            "nt5oDi6z7DCvXAdN33KEn+sBblqHRP+xjlK/ACYyOME5JLCrtYJUcmDME47Zad9+\n" +
            "EFOl1pEOOeAy0an9W9W30U+cJwTMcAh7YHKkzwp+DlUODylL5eDAO0QWQPG+TV8L\n" +
            "Zvss6f2kLKY5YUEVOfMts7460KjhrlI7vf26YHhDZnYOp15FSxFc\n" +
            "-----END CERTIFICATE-----";

    String shCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4DCCAsigAwIBAgIJAKOtsZIcfRgaMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMTEyMDgwNzE0MDlaFw00MTEyMDMwNzE0MDlaMIGC\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKjAoBgNVBAMM\n" +
            "IVByaXZhdGUgS01TIGNuLXNoYW5naGFpIFNlY29uZCBDQTCCASIwDQYJKoZIhvcN\n" +
            "AQEBBQADggEPADCCAQoCggEBAL9dlbTTaHtLFNB0Rnda9uYjnuewU99uoK1bwW9n\n" +
            "NScUdqIlcBTu6xDHFFQSUjC/IkkloHpn1wBg9lUNp9u2YET1/RDQDFYgbinbLv2r\n" +
            "NhUiu8qcX31K9EXkWPILCsjLHTQIgLmvTgzHTOB2PxWUQmlvgjqaII6cFCTNd0uQ\n" +
            "fMOBaxg/o5Vjs6dgVQSwC9u6RcXS2VQuWXUo2pk7H3M6zUSXg6RpzZ8HPds+fyIX\n" +
            "OM5JhLeHaLl0LtwojpSr2yvXifxr1o7uumK+Sp/bAAV2CiN7eC4KX39MWBu6QpaV\n" +
            "tpKSHuXsH8DizlAidPqQsGVZ8AS1tD2mJXpLCXMeT5TkGy0CAwEAAaNmMGQwHQYD\n" +
            "VR0OBBYEFJvw48QbrOMQTsrhzsX9exQ1Nb52MB8GA1UdIwQYMBaAFAVKzUR5/d6j\n" +
            "nYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG\n" +
            "MA0GCSqGSIb3DQEBCwUAA4IBAQCKz1Y29h/bWNdr20pFg/QJ2c4kF93Rp90CJnqx\n" +
            "F6TFaabuFbw/42mjB3IB5RtR/+fz5je5WykII/ST4xQdKCU3reU6zZ3jU9erhHVP\n" +
            "8G1om0hfiiDnYJ3E/03JAzXWWlrztR9fE5aVEAxXDoJQs2gJZJLIQOKjesDh6+gr\n" +
            "FwLb4ltDYHMNlN1HCj31Z8NxWUtnIH7Xv1c93FTCFoeOc9fssNDgsy5FFXy0XIkm\n" +
            "1xrT6gQcxRKoDCC4LwEmLwV3S1OfrNXhgJzx1R65pahAzjJR0vgWU8NbkmY8ZZS8\n" +
            "i6LVVFDar9z0K/8UN1n+nl6saJSUuVFdWzHBRX4wYuUxQI+P\n" +
            "-----END CERTIFICATE-----";

    String bjCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID3zCCAsegAwIBAgIJAO8qnQyTy8/kMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMjAyMjIwNTAwMDZaFw00MjAyMTcwNTAwMDZaMIGB\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKTAnBgNVBAMM\n" +
            "IFByaXZhdGUgS01TIGNuLWJlaWppbmcgU2Vjb25kIENBMIIBIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAQ8AMIIBCgKCAQEAxjz6ltGz06I5BqSCabzxtvma20LcpHHKPqG3D/zb\n" +
            "OS5XaOa5WOawvZUQueIXoDFnH0a/53NzfTPW8ET/0/ls7z1deirSHUmi5gUDCrit\n" +
            "DdyO3bieJ0kMMinjdLGIe8hnd2H7v/X06tU+KilsEFAfFdKyVETa5iffHZRnWUlh\n" +
            "NfoKAU9ycuJ2NGRE0lQ7uSB1ekCHxTNd4rsf0Oqj2xQJfR1jthf/m6rjc38/RkEM\n" +
            "eI1YeADRDKxbDCmFciHs8B+q/pO+q3+o3rKhLXlu8vrJngG3tRsn/i1TQBXjAIdB\n" +
            "sA2RBcni75VqATFImD9TetjwK8+oi1mdBm2WylTPm/y30QIDAQABo2YwZDAdBgNV\n" +
            "HQ4EFgQUW0FY+K5NfCyUqgVjp5vH11aEUlwwHwYDVR0jBBgwFoAUBUrNRHn93qOd\n" +
            "gz9seXFRGQaF7YQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYw\n" +
            "DQYJKoZIhvcNAQELBQADggEBAI8dvj/5rTK4NxC6cNeRi4wF8HDLHLEVbOHfxQDr\n" +
            "99aQmLqDL6rc9LbzRqtH8Pga606J0NsB4owyEiumYjOUyPOVyUYKrxKt5Wj/0C3V\n" +
            "/sHKOdaRS+yT6O8XcsTddxbl9cIw6WroTRFvqnAtiaOt3JMCmU2rXjYa8w5tz/1t\n" +
            "gTwmDuN5u4+N+zfoK0Cc2hvMJdiYFhzPYbie1ffmcHXJTNPqUg9K2lfqDCmZ+xIA\n" +
            "PpVsaCU9401qPWRWftXJgb3vIVOsYB6l3KYYKdOpudaCzSbZVROmC4a693/E5hWM\n" +
            "nc8BTncWI0KGWIzTQasuSEye50R6gc9wZCGIElmhWcu3NYk=\n" +
            "-----END CERTIFICATE-----";

    String szCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4DCCAsigAwIBAgIJALWpkK4pozolMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMjAyMjQwNjIyMzhaFw00MjAyMTkwNjIyMzhaMIGC\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKjAoBgNVBAMM\n" +
            "IVByaXZhdGUgS01TIGNuLXNoZW56aGVuIFNlY29uZCBDQTCCASIwDQYJKoZIhvcN\n" +
            "AQEBBQADggEPADCCAQoCggEBAMGRfNXivzqE3nE2MvAfVaxrNsFrwlgs6jA1sqUx\n" +
            "E+4SP2PAUPoCFcUI1cIbyBacTBTGbrcz1Q1RhledmDzYGcc2Dnhi7MDJi1Qcqq6N\n" +
            "8mfiUKr9HdPfEFi2EIUONqD9afS21lEbf0VNA0+txuXDRNJzudceTRrKxxBjnRNL\n" +
            "aIxYNfbRPA3qnfrgYW0rf7WSAPj2VodwM8Hazfc0dcjqw9p5Le+1LO+wX7u3taLj\n" +
            "8NT+imXBG3SuTrwBQIFq8YCxQYYIRLGyj073uMUr2Z/FMbuHsQZZ3JxD3VGlGxvJ\n" +
            "mvN889O6FgiDGgEYY78Y1fxIBxifY51CjYp6kDuzkZlTyp8CAwEAAaNmMGQwHQYD\n" +
            "VR0OBBYEFCGpWXQSzqv5JZCUpg6prG9txHRwMB8GA1UdIwQYMBaAFAVKzUR5/d6j\n" +
            "nYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG\n" +
            "MA0GCSqGSIb3DQEBCwUAA4IBAQA9AqRq7ikjIXdx1XWvGTBgqmAYXFfyv+wwBoyD\n" +
            "9I2/cEeE6Utr7uTn5uIMlTa7yBvVYdQ/7/pkgGZOO3/oo57MHNHx/h9wLOCjLVla\n" +
            "n+JaI62e/KSv3Y+D7ciGB7V0XK7NNR0YoucuzIDkzDe8/58IYUdvIWZ9STYBmPki\n" +
            "Bebb7WTBhEWBK1yBeLsWDANWW/EdYPsyJ8BkYAmtMGx2Koo3kIAVKtl2/kURLbaw\n" +
            "DcAk4rdqOPW7G5OQrLR4BJ6jza6Fy83qeE/OJB0dslHd3VCxkZsiXII0SA5GkbBx\n" +
            "oCIUJj8Mk5TDtzbuTZOuIoL082j29z09nIFe9BM6f2R0LvyQ\n" +
            "-----END CERTIFICATE-----";

    String jpCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4zCCAsugAwIBAgIJAIKMQ4JqELUkMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzAxMDMwMjE5MDJaFw00MjEyMjkwMjE5MDJaMIGF\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xLTArBgNVBAMM\n" +
            "JFByaXZhdGUgS01TIGFwLW5vcnRoZWFzdC0xIFNlY29uZCBDQTCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBANnHusOyJAxWTaVN95jpljL2OpBV4LH5g61h\n" +
            "U5jBRGSSbBpf3fFCUt8VdtVCbozqVvRDJYT9kvZPRVwhmrhsJMzqkzNXBZUo1ykc\n" +
            "FPRyrRbWYaQPOv9RjTv3pmiSXGeulzzp+UChpYndOsARMcqcejKNdDDvolQk7a1/\n" +
            "6wHoXsVVaEf192Ni+/MLKV6p4UuYE7DDwzNLxSPdEEdAuu21fo27vGZ3eqPbj8fV\n" +
            "CXeqPW9/HkSPnrg173/R78spmjerXo1gvY5EIyfP//uHkoWrrUdGtTxjDg8fatr2\n" +
            "yOG/0u+iMqZLd4lxPDhSPT0xoc1wK8OMbpfyO0Nb2Rp7f4/GG7ECAwEAAaNmMGQw\n" +
            "HQYDVR0OBBYEFJu2pBhxh9NJw7F1XWhDX3aJjKi7MB8GA1UdIwQYMBaAFAVKzUR5\n" +
            "/d6jnYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD\n" +
            "AgGGMA0GCSqGSIb3DQEBCwUAA4IBAQAIUAxyxd2notTBVPkLhfpeRAT9dpcUocs2\n" +
            "d3YEuFE/qktSVC2dIF9k8b6sNVVS0tiUSTXO4a9+12OjGiEV6Qt6s9UW3ZvpLy+4\n" +
            "NiUJJGd275ymPAZBm/rpV7zJT2IZJYMUpO6aZlVxMneHWfT4gsiIDGRGDZwspsxS\n" +
            "VbCnEmO/8KbMxeuYmhBkvCWPdFDAtrRSePMZMqw7t0g+VZDFyXznYtiCzf7PrNbt\n" +
            "3ISTbX/w+sx47iW3viGG+aZqdLRO2f0/ym6kRqtB9Ar1FnJ37dF4CYR7bCRzxiPn\n" +
            "qDfr/QhU/3J6z99A5zFbT1ewJHbdd80atSyGI2CJZdYjXvnq6VDw\n" +
            "-----END CERTIFICATE-----";

    String shfCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID6jCCAtKgAwIBAgIJAPMRW8Xfgju0MA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yNDA2MjQwODM5MDdaFw00NDA2MTkwODM5MDdaMIGM\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xNDAyBgNVBAMM\n" +
            "K1ByaXZhdGUgS01TIGNuLXNoYW5naGFpLWZpbmFuY2UtMSBTZWNvbmQgQ0EwggEi\n" +
            "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0i+nOL3lIbI7sALjUmVMJ4ErP\n" +
            "oXCQO+vltYwxbt6S3raCWrYGCYltB1HkKYP14DqxAxJ2g7R1SNsuHYFVjRBJafmO\n" +
            "Wbrx0x8o+/HNHQ02sTpc9DTM22Dnd/r5H0DsTTrDuZwzqBVcI44LqSrMMMQf1AsD\n" +
            "msmsffvdu3kuESMgPb7wNedMRhFZkI/eY5I5/VWiH7sT+YVdlq5EDfQG+u9tcRtB\n" +
            "c38VpJJhaWjrA2W4cblAlzoIqj+IG/VOI/o0tJVV1VY51fusp+wKQat5dhzs920R\n" +
            "i8eBgnQ9FatZqk/tuwbErU/x/JaV98JSniJyXIFYRI0msdbJJGc75Wl3je5JAgMB\n" +
            "AAGjZjBkMB0GA1UdDgQWBBS6XAbTPnqHZKoc2n9BCgnZZLFBZzAfBgNVHSMEGDAW\n" +
            "gBQFSs1Eef3eo52DP2x5cVEZBoXthDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1Ud\n" +
            "DwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAp1EvUYY05YP55DmxZSn8Spuj\n" +
            "57a+qEV+pm0Go2pNi0I3jq9sB8oGj+nW1A32D26kPMOnR8cSfD/+vQIcNBl+HzSR\n" +
            "zxY6kcHy4q/3CG0sZVd/q8EVlih9LerIEODpRUU0O2EKtmAr49N9avOJ3XNk+zS2\n" +
            "o322x8Ccc5UWfMLn8ftB4FX0X5fph/pOBW/PHyxWijX5eEtFMBj+MrB5QXJFhw8w\n" +
            "362zOFiVxZ1B9RJVCcMEpaBfg0wU+rzIw+bm6XhACZq+g2cNAsE1n7K56VWFpPYo\n" +
            "Df3ZKekj7Tw1vPLcOVRAJVqhSeIWIVhw4P45gPzLlTxAkSIofkdhIvVQRpzjkQ==\n" +
            "-----END CERTIFICATE-----";

    String deCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4TCCAsmgAwIBAgIJAM5z+GQ6YhbZMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzAxMDMxMTU1MTdaFw00MjEyMjkxMTU1MTdaMIGD\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKzApBgNVBAMM\n" +
            "IlByaXZhdGUgS01TIGV1LWNlbnRyYWwtMSBTZWNvbmQgQ0EwggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQCwmvB5AgLFeBLD/nxltk1yajtHyWnc5fJOtBAJ\n" +
            "oZL8ig1EJVpCErIRNBhSwvGK2VhGacIPtY55KRSmkQX4gtBHuw1N0YSP7puE+PyP\n" +
            "qEtHsZfTry1hERsJsNF0AyLh+28dM+PMC36OJEdHezjf7rVRubTcKZpBn36MCl/M\n" +
            "Iy20CRyqe3ESc/qSX//YHBDnIAEAbm3A/U4VXnQN8RbFQaUBstKmpgj6N7mXI/zQ\n" +
            "tZEUtlJEaVBAubg+L38b0dsxuL2h70xzFSF2ANTHea0e2ZLOaI1URFxlkIdnoin6\n" +
            "okvolnAtlrQHnGtbgvKRrqZrh1YIzUKpvpsF/SPeSZLnl76DAgMBAAGjZjBkMB0G\n" +
            "A1UdDgQWBBREHMheMSXr6Ggvtthov6HBPDt3ITAfBgNVHSMEGDAWgBQFSs1Eef3e\n" +
            "o52DP2x5cVEZBoXthDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB\n" +
            "hjANBgkqhkiG9w0BAQsFAAOCAQEABxrQRrHOZWlWCPq8ystEe3i4IxUenYTuXShh\n" +
            "ZEX1AMcDhN9haZwAhD3eGjqWbXedsJZDgSnp/bYpqfGbBezZyZCw7xyYeWWU7Mxo\n" +
            "WOCwv18owC66FWOKZb65MLqB1bqiSnKPbPdpTxWJ1CKP3x461p+gy4UQQ2Gobq43\n" +
            "gEv7vRcpDnuss/uH1rSlWCSxNE9dT4NP/lyFb9QIWA3hz5XSmG/QhCqUB35q4M8H\n" +
            "Fno+IO/bN4n9M78TibCNeguRdp5s8SbuMIuIN1YLO1ImeSmlFSe01xmfLEpmT7R6\n" +
            "dxE7bz3X+cG94t3osfcLG2HpWfje1N4b8Q0+0DM7fkLkE+XWeA==\n" +
            "-----END CERTIFICATE-----";

    String hkCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4DCCAsigAwIBAgIJAP36lKvNIXHQMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yNDAyMjkwMTMxNDFaFw00NDAyMjQwMTMxNDFaMIGC\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKjAoBgNVBAMM\n" +
            "IVByaXZhdGUgS01TIGNuLWhvbmdrb25nIFNlY29uZCBDQTCCASIwDQYJKoZIhvcN\n" +
            "AQEBBQADggEPADCCAQoCggEBALcxa1245JSf0c4JrnpbisFnb3LSxdWOrA8z5MpT\n" +
            "MHxLbGCGv9HN3OsZ15tB+/h5Mi8Y17SJTof7vLUgK9lYUd2wmdD5HsIlsXOB1Osi\n" +
            "rY8WTY5ARKUuvA7oT71JVaORnMY2A1SWxQM4ZFTO4EDWer01l75rKR8jvjNkPSar\n" +
            "kMQ/QYjxAK7ByfjVTwY9/j9RqDyZzPHaz4bUEhBbsJL9dlpVhLZn0zcifGqG5WYE\n" +
            "eOEyQMU2CbgWCyrJRaQmAeaWkhBLUKs1JorOnNH48PedO1U9LRqo3gyu+vj2s2zK\n" +
            "TA/6/0kOFDeCUwc45b33dojmvAJv+ZUIHacKWNe9nU2dTpMCAwEAAaNmMGQwHQYD\n" +
            "VR0OBBYEFGZZ9MoUkiS5SHwGRYUQbKk6LnodMB8GA1UdIwQYMBaAFAVKzUR5/d6j\n" +
            "nYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG\n" +
            "MA0GCSqGSIb3DQEBCwUAA4IBAQCmY1ohTV7NM6HSBYSLl5WsbZeWH5bx13bKO5BR\n" +
            "hyBodowaTL/Qp2+uLdKoj52bsdcq04n2rVIAQLCP5sIzArcl/ChHBSGwyNYy2V8Q\n" +
            "I0Ld74/OP8tJa/WhALs4TJU6bf5jtNRbSENNvIcSDYOQjuI0lV5fBRNSqMvEwh38\n" +
            "sB4w8+w5yWnt9IXrnvWD0fu5wFpNLNbSZfaE0DZbf/wh7jb68wlqAZwYEPrd0TBw\n" +
            "4GEPTef+5rcrtS61vUP1NQBCk27e3zcL7WzHc5XNFQZjnYTgu9+5yMuxN4JVeOaD\n" +
            "7dOkayeFfJ1YwJoGV6I+UN3qwgCCfwxkxrGjhwFayLDdQdBE\n" +
            "-----END CERTIFICATE-----";

    String zjkCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4zCCAsugAwIBAgIJAOvkXLhGC6sfMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzAxMDQwNjEwNDhaFw00MjEyMzAwNjEwNDhaMIGF\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xLTArBgNVBAMM\n" +
            "JFByaXZhdGUgS01TIGNuLXpoYW5namlha291IFNlY29uZCBDQTCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBAN49g2GLadz5pCiQx0pqiIag15R8pxG0BbTS\n" +
            "tvywtYaIRfXu8I+oiTrhU8FqPRrGk6BYegwH5vq3gA65h/vqvJsuS7w609c/wQNA\n" +
            "GyHIrKQ3vyJfFO9vJzQSoh6MxY6lJu8PVe2JabpjMosIBCYD1oOHgWk/fMdqos+e\n" +
            "hCwWJt8fO1uE+QrizQQtDv8kp73QjMWibQW5u6QpHLl+PF89svsdsEOL03D7bX7i\n" +
            "h2cOrfra9QF5tfxGuOEMggOCktiCZX044nFVm7hKLorBjNGPn+oMMSC86tdAwjlu\n" +
            "IDkLgarayD8la/6tYi5k608Joio4HhaNK9yfaQObt/TteU+7oG0CAwEAAaNmMGQw\n" +
            "HQYDVR0OBBYEFIve94pqt4QvZJqzmqeQBbgi8FlNMB8GA1UdIwQYMBaAFAVKzUR5\n" +
            "/d6jnYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD\n" +
            "AgGGMA0GCSqGSIb3DQEBCwUAA4IBAQDE0P8qNbHridfx1aI8G0YNpp5ugnUc5VQQ\n" +
            "Q/riX9gXZTu6m2g9ErG1Q4Ld7R977rirb6gN345XUvGQQ+rQ5kcnnzG27J8fwqCY\n" +
            "IFtc5p20Btjca2RVuN6rjakuCeCSZVK1UQExzsOFG/MM/0ur32IJLUOA17zWsCXb\n" +
            "Or32tyCTeUTQMGUpWxhlxOLqgVhYf4hQSbyRdcdX2rABg6H2bJor2/oEQkBd6HZs\n" +
            "/V7dvCO8ddVdFBQ84R1IxYNYwsd5bwHXiQoDrfybHHjt+irU43+D/GcpIVgXwdxs\n" +
            "vkOwWtSxFETCuxVyWSpxzJr/rIGnREVZ6kcy62ctv7CnYWflNl1N\n" +
            "-----END CERTIFICATE-----";

    String qdCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID3zCCAsegAwIBAgIJALIzc2LtbEasMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzExMjMwNzQ3NDJaFw00MzExMTgwNzQ3NDJaMIGB\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKTAnBgNVBAMM\n" +
            "IFByaXZhdGUgS01TIGNuLXFpbmdkYW8gU2Vjb25kIENBMIIBIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAQ8AMIIBCgKCAQEAnsJNATB4nocxGCA5o3XABxepeweGUnjkZlb1eaET\n" +
            "rAS2f5Prc2q11U0o/jY/9jpv1Ug+og811zNffSdHmMx+tlpELhUkpkZPZNi2Wz6P\n" +
            "weTQ7ArK+kHqMA41Y3CTHV5mHPFcGacDDwvy9+PZK4E0+nmLBQejrFqcE8WMiQUt\n" +
            "fT9TuWlzOGV0rozAUVve4wFy5oUOI6zHqyqEzGmQK7ULYFuORCdjW8rBHviwYU1K\n" +
            "gLfSkqcQlbtt/82Kg+ALNCmJWgn328GntNajaAt7kdjg2WgNfqXlDu3ojtItgrkE\n" +
            "+/H9riphS6ke4AS396IBTCJpHswkpf7GnVenoSuD/pYKCwIDAQABo2YwZDAdBgNV\n" +
            "HQ4EFgQUSdBg7whyOf5Wg0ekLsbh5Yi2MWQwHwYDVR0jBBgwFoAUBUrNRHn93qOd\n" +
            "gz9seXFRGQaF7YQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYw\n" +
            "DQYJKoZIhvcNAQELBQADggEBAE5PsIBN3DZsWW9cmxgHJCz8a1UFyeg7Bk62MbMg\n" +
            "DdrjDSDK42wO9GnkWN+PreYHUVmZbgDJHnbdGyLFQxImpzaBf2X8txwO8xZpryBP\n" +
            "Ugr0K5U2qQcf7+9JNDBprhqA3PW5fxQ3yJXN1CJkXb8Ij+jV5z90ewX7asVJLphF\n" +
            "gEVZwBv+iY8He0uSya0LDdpXZfn/i34zRhoLTkwaPptXvmcgDi4g2EoA6fevHtAZ\n" +
            "0tU5hoQ1F4elPOEmIGNfxokENQAJR53yooofgyA/eoZKlfeaAEHR3JbwlYT+f+/z\n" +
            "gyqTwPbejwBZq6yOZp9ynLMSqp4mH7DDZ4ewhlbbQWj7l3s=\n" +
            "-----END CERTIFICATE-----";

    String myCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4zCCAsugAwIBAgIJAIFM+f/CNY1sMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yNDA0MTgwNzQ3NTBaFw00NDA0MTMwNzQ3NTBaMIGF\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xLTArBgNVBAMM\n" +
            "JFByaXZhdGUgS01TIGFwLXNvdXRoZWFzdC0zIFNlY29uZCBDQTCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBALG7I80dIbiRM0VtA+YoqBYJWlM7QHHZvwP6\n" +
            "iidW/rgQONK1t5W0RqFzpuIWlElC5+uLMyuqwtsFwzVYWaL4bPkhg07hk6N7mfHA\n" +
            "89asRuPHj6YvRs7768HsgmYgf39/iMqZJvbRMz+mi9PtwNg7w5bz090Lg5Yo7WzF\n" +
            "UQb/ZwDhy4fXUaiF9vo2y9Zv+QFlZ0mcMJ3uVbn94MtW0k/+WN+WdLrmjfGJbg8m\n" +
            "eDlL+d6+KvaE3v7/q9pf+pJF4PEttgKVvWbhN4rCmQxWxpAfvrmFfXX7IvhqTFOG\n" +
            "kLtmRnwdAcT4s0mylFn4D3kV9tQyxkyRkLixm6Ruu2vvJLjDrXECAwEAAaNmMGQw\n" +
            "HQYDVR0OBBYEFIi6ptE3kdvsNBlwXZH4qNJaPZYxMB8GA1UdIwQYMBaAFAVKzUR5\n" +
            "/d6jnYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD\n" +
            "AgGGMA0GCSqGSIb3DQEBCwUAA4IBAQCXYi6Tn5qufLibv4WzeoYOY2emVcc9cu+6\n" +
            "UiLxnBPGS1Nz4jGzzmTfH/H81ZmjZZ/9JweC1cFRrLfe8316QejDDiWWFnZxV+Hs\n" +
            "qBzArdMZh9vW+r8FdECIixjOu8YBc3pEbZyn7dHb8EqeibeJpr8eWKWi0qwVSGKa\n" +
            "W4r9EasJROABhstNHQFTGcatIRVw7PmKDYXBRtBUM1GuX0ljHFaV+cgr3eW1hE/d\n" +
            "6aEq7vtty8wrlkOENW2QeYvBzVRDsw+zaejUI1E3xznR7nHkjMoz6Imr2Sq05gl6\n" +
            "8xqQO92yxldq31B7ktM+Wbqktt4djq4gPZ/cXKZJieOovyMFaoaR\n" +
            "-----END CERTIFICATE-----";

    String hhhtCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4TCCAsmgAwIBAgIJAPhgCcLWvELzMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMjEyMjAwMjAyMzFaFw00MjEyMTUwMjAyMzFaMIGD\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKzApBgNVBAMM\n" +
            "IlByaXZhdGUgS01TIGNuLWh1aGVoYW90ZSBTZWNvbmQgQ0EwggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQD7CyRuZK0fLBUdnZn0CHoOSA/kE56k9XMcq4Wk\n" +
            "WA/10BEPzI6C081n+67mT3zI2Xg4gKfdTcb0Gu680UY7zPy+ySjoUy+y62A3zSjK\n" +
            "GQm6THLIh1C8az231iDUdEsV9pst/cvTwjj3Indmvd8BigGpFe5GqDeaAC2Jt8mP\n" +
            "OcWPe/tKTP49lPPfTy+YAzUUek2P4oiDR4su9gB3qifxe0A5DoIihrxHqw1hsmNJ\n" +
            "cfp0TkkctJ6ZaCp8WE6Vst+6rSeYPI899iuCRrPAXXptw84n618mT3eKp7MflKS3\n" +
            "lJTEV8pVPwFFiPWLZ4EzJUNpxUUK4iuVYe2IFlh0ySeIR2hDAgMBAAGjZjBkMB0G\n" +
            "A1UdDgQWBBQvlnmkkV2D3JedUKU44UCG5fkHvDAfBgNVHSMEGDAWgBQFSs1Eef3e\n" +
            "o52DP2x5cVEZBoXthDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB\n" +
            "hjANBgkqhkiG9w0BAQsFAAOCAQEAaPU1bY38AiBCTdxAodq74rD6rDI6fXVRJ2u5\n" +
            "AOpJFP78RaLJ0AI+7Wvs1w5zOC1Elcw7j0Xo6iqZcS/aKvt/B74Q5CyLLkJN9Gc6\n" +
            "9ge9YGxSDq1YEacM2n2ipkVTc/gB8QT3Dra8cuTJHAsbrAh7wdnKmQU6L1Z632XJ\n" +
            "EEWXzoWiwTEKzaLTR5ezhSUxK2t8BQtml6heI19Q5Xn2OK6QeaX3DfMf0fSl+/9h\n" +
            "DTU0jtAMBao3EKodLcPNilcDlVj+wn28bM30rA/93LDxjWHDxFIqg7Ujbul9Pp9m\n" +
            "p1Q7uMAUGCwA+CBT88PsOMAIUtYQ23eNu/Va/VEL+ZbfEiGm0g==\n" +
            "-----END CERTIFICATE-----";

    String usfCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID3jCCAsagAwIBAgIJAKRElw0BM+QQMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzAzMDEwODEzMTNaFw00MzAyMjQwODEzMTNaMIGA\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKDAmBgNVBAMM\n" +
            "H1ByaXZhdGUgS01TIHVzLWVhc3QtMSBTZWNvbmQgQ0EwggEiMA0GCSqGSIb3DQEB\n" +
            "AQUAA4IBDwAwggEKAoIBAQDLOhmPZPUMdQpgEseUQtAnVK2jHu7czE1QwewQ+Ex9\n" +
            "MR09Gfr2pHf2nV1dLJW2KmeDenoc0LZTVhOdtJofOauKZdlF6Ygde9eXAT8b4UYd\n" +
            "YMPzEHwVPI9V/ppnimkXCPIB1mMfLX5WmeXMii5QnnpI20oAeJR6bEEH2rqDT8Nq\n" +
            "gAP0MBxb4dmnMtigRB2WMe9i8ALHyZ73TduFnBjPl743uxGVvOUUMWjCQ7k+wBhP\n" +
            "hRJb3fICTTIj5pVqLYaawUhawvf7U+sCmrvdBicD3l6/wIcjuwfj7AUo/qI1UtjY\n" +
            "UW8Rs3QI6Qx5bVbKs3PsEIwGwyK/ooZDlrtn3037tdbhAgMBAAGjZjBkMB0GA1Ud\n" +
            "DgQWBBSTH9bexX7pb9iMlSfc1sOLmy4qZTAfBgNVHSMEGDAWgBQFSs1Eef3eo52D\n" +
            "P2x5cVEZBoXthDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAN\n" +
            "BgkqhkiG9w0BAQsFAAOCAQEATMKMHgLo5E1K4lfk9XwOtDgcgTx/Y7xjwHoPDQuR\n" +
            "ZeQ7o3ixTZ4Ws8IVbCMiNNYqU19+tYJHm14BIu5kWN+dwO85dOYGK+Wpe7Xm50nj\n" +
            "mGoYVNNgtQNy3RtTAC2ezzaCZV9VoGnEJlwuMYXmrcnKyiKa+vtWI4MAXfOtON6J\n" +
            "s47/ORwCJ4HTFDIurb/KKWopymuJkeY9iAIeAxr2b1Sel8hBFYoVBLIg9cc8jMc7\n" +
            "84REE4fqmLG6q7TH0vn7WVCE3BHkx8UxPIxsUt1cTaRovoi8TlncRx7oqNL24ZhO\n" +
            "mzpuwbUHoKo76k0XZGBJCbe499IR72rVpVpT1uITvnjV0A==\n" +
            "-----END CERTIFICATE-----";

    String usvCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID3jCCAsagAwIBAgIJAJ1cYTArWPdJMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzAxMDMxMTE1NDVaFw00MjEyMjkxMTE1NDVaMIGA\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKDAmBgNVBAMM\n" +
            "H1ByaXZhdGUgS01TIHVzLXdlc3QtMSBTZWNvbmQgQ0EwggEiMA0GCSqGSIb3DQEB\n" +
            "AQUAA4IBDwAwggEKAoIBAQC5itCQ7NNojKjnbckuSyJ9aIksYeU/qUDvi7zFVEgO\n" +
            "PknMmjGxBOnCb4/TI3wYDIGwLLNTF44fvmUx5MIE6T4ehk6LC8AJfQvYuhE39X6D\n" +
            "Sw1Ybtv9sgJZqypZBpPgIO0/It47/tm3DSNlaVFu72maxywJPsIiqTCXYRgUUU+H\n" +
            "lRScQ0qTO+4Fb67SuszvUtSWnB9iB6YlnHUQ5cqbieeWcYZiUnaqHngDVdySFDYw\n" +
            "eIcxJi1zwBxOlfq/mxrZyxhwxt/b8Z6H609sEVLZ2oAWjBQH4TNWMHahkREtwttb\n" +
            "qZWV0lIh/AzOgbOWK3ouzf/KOsXmTiIfUVSRZNRx+wmjAgMBAAGjZjBkMB0GA1Ud\n" +
            "DgQWBBRa4+jNx1GlIhCKbB2PapcPAuMMUTAfBgNVHSMEGDAWgBQFSs1Eef3eo52D\n" +
            "P2x5cVEZBoXthDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAN\n" +
            "BgkqhkiG9w0BAQsFAAOCAQEAJPhFrAmXBQnJIa5ORgrxkCuc8iU8IirZKZSCZodx\n" +
            "BFi5Nyr+m6mtJbe1AxoFXkwVhPpLtOvm/rXWWVdDDhalpPPBjhdpVbiTpIQlEitl\n" +
            "orKEn997Fd0YI54zHslCNBbAbW81YlxPp9cmzkOXejdeoQqmvu/6O+gEFmlLbymT\n" +
            "S5MJriJ2y5M+k3xZrx6ZlS+ZxdD1dml2rLioFr0dhkuk/EHFd85iRWyeloutACD1\n" +
            "Z1sSPw5skUr4CO/SPrSGFb609AJdRGVmMDMpcM8YvqfeUPSHCzJCYHEp4Il0DAyn\n" +
            "Rm+Ka02nh4j+5H+4wYLWuc5sKsSPNTO1FpV3xr08tKHljg==\n" +
            "-----END CERTIFICATE-----";

    String idCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4zCCAsugAwIBAgIJAOhU6JWRIW3kMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzAzMTUwNjU1MjNaFw00MzAzMTAwNjU1MjNaMIGF\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xLTArBgNVBAMM\n" +
            "JFByaXZhdGUgS01TIGFwLXNvdXRoZWFzdC01IFNlY29uZCBDQTCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBAMLGCl7+MNU2GemCj7l4+f8937kITZdRnnJM\n" +
            "+TlcBx+TDB24fsy4qV1rPc3PX5t/l+ZGqh2UCUviNZwhkflAVjf/nSOJbgCZh8f1\n" +
            "BXjsKiYSoGHEKt7SYipZ+Ihagw79L3xgusGq9vEgByvuAqbDQ3m7wPI8JjreEq7M\n" +
            "xXzPG+YHOMN3+IEj8jHmeIGGBaBHp+hOpc6dknJq4iNSEmFmauO+KTQTvMva6VAd\n" +
            "c8xenY9pJs8unP2L6hlkEwb1m7oOH81pA9a9cdqUNUjj7+BhCjSkOkWWwche6lUY\n" +
            "OesO8kB9Mp/n+0s2VmQiFi2fuv9B0N5KxZ7fx6e9LDcvwwqkJ5MCAwEAAaNmMGQw\n" +
            "HQYDVR0OBBYEFMzjafFC2ZOhKDYFAE76WNDbK5ajMB8GA1UdIwQYMBaAFAVKzUR5\n" +
            "/d6jnYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD\n" +
            "AgGGMA0GCSqGSIb3DQEBCwUAA4IBAQAVq8uSuHNgfAO93mSrLBM8epuYH3VzIZE0\n" +
            "5GB9TvcafZZx6k6LASfuNO1VMAjltL0qUWPPVc/7InUW5Y1c9JEEFClvPOEnpyZx\n" +
            "XqNq2vKDqJy1fmPQvLO5wpRHI7s62Gzc1cteWw9SYUBnZqBJXovzGVRJxmaDLwDx\n" +
            "TofXUYZ7NFvX0VPB4zSO0XyNFFrK3kkVTod/U1mkvwZLOlJW62rDkbGpaAiNhdrQ\n" +
            "2EuB7et/cVV7k8LR9hMmyOQ+41YvwpTeu3qb6baY2dGg+nnVaKbG2xG8Rku7dyho\n" +
            "8+PeaIvrSfrcNHeXp8xh/RqqrBZD6oJxwF0adJy/bjS1qtkZsIHQ\n" +
            "-----END CERTIFICATE-----";

    String cdCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID3zCCAsegAwIBAgIJAMfJ9PSh1DCRMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMjEyMTkxNDQ0MDdaFw00MjEyMTQxNDQ0MDdaMIGB\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKTAnBgNVBAMM\n" +
            "IFByaXZhdGUgS01TIGNuLWNoZW5nZHUgU2Vjb25kIENBMIIBIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAQ8AMIIBCgKCAQEA5WAykiJO9SnhZuuWmcxuawlt5hXux9r7kHjiXBny\n" +
            "KFYhWB4S7/syc1D8ltaJ56Q+NjPEHDyPlE87+IOju7fSN4Yvkwj4MtSF+2Lf4VPf\n" +
            "TSBdVYba94jESYl8EHwJMTNFp1Yg0+jVqZuL/7USIvC/QPPq8VsBSb/mKQdNejK2\n" +
            "3bk8MoLK4n0RM3NI21qm0KOwif9cFsBdJ4AsDU9TuNomH9+gF3HWishgkYdT+iIA\n" +
            "XomIiXTpeMwA4ooj1xAAV+TI9hueo4PH3XCiqTIi8CjjhE+ACT3QLvlgEMkO4r5L\n" +
            "A36Kmq/I2gPKYPPJm2z8k7S2jWyB/2fYw6mZ12jIQDFfYQIDAQABo2YwZDAdBgNV\n" +
            "HQ4EFgQUbGwQCD8iaDajh0qJV2ljh4bjw88wHwYDVR0jBBgwFoAUBUrNRHn93qOd\n" +
            "gz9seXFRGQaF7YQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYw\n" +
            "DQYJKoZIhvcNAQELBQADggEBAFnE2Kec1B0j/b7NAT1DujV6ukZE+++rCdVkwOHt\n" +
            "faIkUow3evGilzP1CWFabieBwQKZ0encA+10QWMMQV1WXNMNPYkCZ3fPfe8kOgeZ\n" +
            "Gd1lJ3w0XbXT/UPMkBfGuZ5RF+UnG7O+5duqfxDfEeSx9Lsrnwv9EDKF8+Rtk6JD\n" +
            "Kw/N7bfWxG39mmCUDHXIzDmrZeP/G50BaoudE3REYOY9KmiH52m7Aitx+u1PCw3h\n" +
            "qlOCFAlVxZlTiUFFL8A4670zymmxiP0kdM8i8fLyZnqfKGMGYbrANTUVqPmRk+fx\n" +
            "eSZGuwQDWWBcBQnCraDj+q7S5IWZkwQZlmplNPN8zHMLSCg=\n" +
            "-----END CERTIFICATE-----";

    String gbCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID3jCCAsagAwIBAgIJAJ4Z26VpjVEMMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzAxMDMwNjExMDdaFw00MjEyMjkwNjExMDdaMIGA\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKDAmBgNVBAMM\n" +
            "H1ByaXZhdGUgS01TIGV1LXdlc3QtMSBTZWNvbmQgQ0EwggEiMA0GCSqGSIb3DQEB\n" +
            "AQUAA4IBDwAwggEKAoIBAQCtijKBod0g7jyfQJ1K0FGTVxWVOj1VqFv9q9GiPlGG\n" +
            "bIUDFs+iiYNq+F0kc/TSM4HI/CU6kXr+L4RK0v1mBQqmbYWmLQ3btjpleulSDUgW\n" +
            "WyMUXH5UMwRls6WSX/795avVB5noA8D+7qRg1oOlJAD+ZQaN1t0qjS+f41Iti8uU\n" +
            "8L1ewihauCH03lSkvGSsRMOc5Jl+F4SFs6dvoU+T8j1G0oMA4MP5mE7AUuZBfhMK\n" +
            "vmNYcSPxhQI82gSKQZMhROhvUbEiMbe+osn4hIeBtfRQ3O+jlHj7B5XW1AsIZi1k\n" +
            "S8lj9GfmIkBi9viKOj7iWKwghTTY9P+79f19Cml5e3XbAgMBAAGjZjBkMB0GA1Ud\n" +
            "DgQWBBSo2DCQBfzreXWwyj38B6j/orggSDAfBgNVHSMEGDAWgBQFSs1Eef3eo52D\n" +
            "P2x5cVEZBoXthDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAN\n" +
            "BgkqhkiG9w0BAQsFAAOCAQEAIBUAPxkGFzh4qBR5tCRqLvoptr2GNH6XRgDVyDKB\n" +
            "bMX/GKIvi/CR/2KehuxkFO8gyMMRF/ZQUXFp/Or0YwPMaJO9C6OgQcdj3kAuITwq\n" +
            "u6zU8ICZK5tBp3kM8LAY7AJJAI615PjHe5Z9/+EjDmRsvMNQrVg2yA9rJRirtFZP\n" +
            "F9jS/ahbBmRxwFdckXQIErwnfL+BwU82tlq9mCd4ir1WnfTzh/WTAlRkGMQGz16k\n" +
            "um+O2DrEfqs3RqaY+nTvKTamLZ3Kkvk0lFdp35TaxeYZ0UqTDnEOCIlCGHwVtVHC\n" +
            "Go/k2t14MBN1U0qQzqmDpIy57f+/URKgZhQ+KumrT5TVAQ==\n" +
            "-----END CERTIFICATE-----";

    String hyCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID3jCCAsagAwIBAgIJANo1E2InQHt3MA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMjEyMTUwNzM4MDBaFw00MjEyMTAwNzM4MDBaMIGA\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKDAmBgNVBAMM\n" +
            "H1ByaXZhdGUgS01TIGNuLWhleXVhbiBTZWNvbmQgQ0EwggEiMA0GCSqGSIb3DQEB\n" +
            "AQUAA4IBDwAwggEKAoIBAQCbhoCuL7c7P2ykiu/NlFQ/9ejMqsTRmfOxPotZfm2b\n" +
            "NSEzIitIQ0lJolH5j5shvria3qVuAWHNV0e9sFjAp4Zk9kNhOM6QiAwynld5id3w\n" +
            "rleWhUtkHu1A8Jkhoc9RgO64ALJEiGI3Hrv8aq5Nu0W9xaIChKvONvK03DaGnDtw\n" +
            "Q3BjglEx35rTH+6MspdG6Rk0xhPM1W7dAYw/trZDfeG5uCXlbc755UDVk2Kh/jaD\n" +
            "1+UcXDDX089Zz1qzyOrHCBwWUK5LVjWD1slf1Fyhdd+Rl6kTsJwpp6M9cXHULUU4\n" +
            "b2LxDduIHO+w3JJyn6Fj+36ClkDw9/MspqxxjfqTQ3dHAgMBAAGjZjBkMB0GA1Ud\n" +
            "DgQWBBR+Awr2ARs9+wB4VY2vqGwpeH1zfjAfBgNVHSMEGDAWgBQFSs1Eef3eo52D\n" +
            "P2x5cVEZBoXthDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAN\n" +
            "BgkqhkiG9w0BAQsFAAOCAQEAlTyaApORidCQxhxrMG6HCqsLTy3xYyFFEYRbixeY\n" +
            "aSm1SJc0bKGugMvGNR5rmR0wJdgsQIUgfi56P/QoopMgZ5NAit3I6iMQ1BxZ4ZuC\n" +
            "ftU4KClnFeLgIxmhpQ7+TfwTrG9q1MJJ9HGgStzcgemeISg0Q0Dq4DIzoCioVijU\n" +
            "V6slbvRsyjrXjSbnPbQC41wNO8nV8jYl/vIwj+onxUoJuvjL1Nqn6vX53WpQH0Bq\n" +
            "1B6PgVGj6dqHKpdMfYhglzEeNMgSc9A8am1NSGvhJ+EzBWhoNI6bwEUzBOoFDN9q\n" +
            "bdBE3ActxrGP9MaYCs6cJPNwsk7E/ijZTYhqd06dghycMw==\n" +
            "-----END CERTIFICATE-----";

    String wlcbCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4jCCAsqgAwIBAgIJALlJAIErjo2JMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMjEyMTkwOTAwNDhaFw00MjEyMTQwOTAwNDhaMIGE\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xLDAqBgNVBAMM\n" +
            "I1ByaXZhdGUgS01TIGNuLXd1bGFuY2hhYnUgU2Vjb25kIENBMIIBIjANBgkqhkiG\n" +
            "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs0ih9F+2Lq23WFAvgZWdyXToSPuYe58TfyPe\n" +
            "4iG0bhun0JjMRKWdpMHLuIosQyisY2ANf2P4U1Nih+zQ/I16jyKEyb1A8kgNPWRV\n" +
            "oGiWLTDZ2CDtp7vIHd+grhjJhPm0s4wjO6JZT3tfXOYTyxFOD/YxjUnR7EpzHpla\n" +
            "+mM6bC4ktq6qCc/zYQ56b4zYYhZO3jY6DtRtDCkxIacmnVQAj0hkOgU8OFUn0Ar/\n" +
            "jeJW+H+XsaUQY4Ex0UHRrpzDsw724sni2GIbKAfZ3WB2LzEaSmr0H4tgawtEVUfj\n" +
            "2uPFwQNFjOj+wY2aS7bOJlXPqmFjL3Ug/LidH7cTy0PZxsjx7QIDAQABo2YwZDAd\n" +
            "BgNVHQ4EFgQU3iDnyrEPO+4ASAcMXAXZqXZvIPswHwYDVR0jBBgwFoAUBUrNRHn9\n" +
            "3qOdgz9seXFRGQaF7YQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC\n" +
            "AYYwDQYJKoZIhvcNAQELBQADggEBAIG+VMc1R9ioNG1cqA94WXJj2UPAPtuMD9FQ\n" +
            "UE60see9Na5r9M87yce6YJ0UBpJZGG03QuIAmI1ogLblaiw8aazPouZZqmxlWt1/\n" +
            "nbgt1XiCaylMKJSWwvO++O/Sz+o8rf/P9eWj77YtAlzSVxNjpolYhzANYMYuA8Cx\n" +
            "VGH8hctEE52rL9VAUCDA3bCp2P/tKtwl1LaWMriNvmbT7wD0yuc8DuPSPUX0Sn5o\n" +
            "7LsyUhtSQcDuYG4DliWR42N2LAkTFDlEjilKZuI4QbDTWb9wMXMt03m4cHHoo+b1\n" +
            "LQeRq8Klk+3vXPPGoAwLYqN5bJKSZVoN7yJ3jU0Q3Nh3pIbmtpo=\n" +
            "-----END CERTIFICATE-----";

    String gzCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4TCCAsmgAwIBAgIJAIZd4FNiKYb2MA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMjEyMjAwMTU3MjNaFw00MjEyMTUwMTU3MjNaMIGD\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKzApBgNVBAMM\n" +
            "IlByaXZhdGUgS01TIGNuLWd1YW5nemhvdSBTZWNvbmQgQ0EwggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQDPZhEa6BMTl8eaKreVeMImePOXGJ83UI99KuCK\n" +
            "CkfCn11/CsjoNdkFeDgR3SZMGfva1gFuCGCGz6TCdIxa/HDs6BpopaNlLio6KKMm\n" +
            "86T0Flt8RCh3J5MqElmoIGOhIY2cufeZw5PNAhsU32ZQVTwYGkog9MFDxvSROGO3\n" +
            "V7q69Bw3jPM5C5bNBlyfJ0y4l8LTXAt3f9RjgsPTxvF8knEc0ZXZPcdQAucpGGlX\n" +
            "1kAcEGZakmy8pEOlqY9sUYYgL9mmjZyDpIlPBYhvsRQaN3ShYX5wb6I9+yzPTR2b\n" +
            "a43DVCVPtX+y78lauoE+eNut5cbwvG7iUMuhSgD/3M3/S0uVAgMBAAGjZjBkMB0G\n" +
            "A1UdDgQWBBSHJm7fihIELGF2FPE8gFWWdAEZQDAfBgNVHSMEGDAWgBQFSs1Eef3e\n" +
            "o52DP2x5cVEZBoXthDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB\n" +
            "hjANBgkqhkiG9w0BAQsFAAOCAQEASABFU0xmJcpuFdnfXwXI8bSCzUN39CQGeaQ5\n" +
            "xZh5uMnE+rA7dYpSCaRGi9C5v7R5smFAXVoZbk0oszuybMzAv7r7rv9CTf32gYpw\n" +
            "yciedtgHJx+zqkB0KGA6ZKRvZoKiplujXSQsXUSWkDJMWSIiCXxGS88/8/aebHJm\n" +
            "+d2rpg2j10YpuKrfboBKGgrDYZxTLpsDRRkh2jciNxMNRDNEQXaDBL6MPpntqf6v\n" +
            "3ya1sZXiByIZhUrm/yCgrT4r+5fvUSbukdRnVP0pGcEs6bj3MaHm/XJNUemgPVbo\n" +
            "mzM48N0Lz3rLQH7bb4ASdXWGClZWldLcNW0N1HTcLpAlGwAyzw==\n" +
            "-----END CERTIFICATE-----";

    String mecCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4TCCAsmgAwIBAgIJAIJ3zG5d7DxoMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzAxMTIxMTI5MzJaFw00MzAxMDcxMTI5MzJaMIGD\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xKzApBgNVBAMM\n" +
            "IlByaXZhdGUgS01TIG1lLWNlbnRyYWwtMSBTZWNvbmQgQ0EwggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQC1FxY72GFU5O2YrowniYQM5vzBrhJn5b7VHKho\n" +
            "lgFf0e3DwloePbo1ffWOktkuK5rqonwNh6FzkIxD4KuYA1WKPQNFMLpgGtRsj+eG\n" +
            "7AzLOjmOYgWQZAR58pEnL3uH4SUR9aAEHMLJv9MXF0RT80fM4oOETFekEBtJhZaK\n" +
            "U7uW5MlymnWPam5A/Og5upw4hKu220g9ofWwxs9KJJBNgnipxf1p+e5HZ+vzjbtm\n" +
            "Z2wc27KKqdEPx9Kilt/cUqlq4/7GluTF9CAmA5LEt7al01luqzNcJN2IcO3Op6uR\n" +
            "tnbRhWZuER3hCKl+7mZop7nUJATf/ouWhNl3nA88Neq11WtTAgMBAAGjZjBkMB0G\n" +
            "A1UdDgQWBBQwAoDAhQRGtXKdIUgYTJPaLRTCrzAfBgNVHSMEGDAWgBQFSs1Eef3e\n" +
            "o52DP2x5cVEZBoXthDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB\n" +
            "hjANBgkqhkiG9w0BAQsFAAOCAQEAGKd0t4wc/pJCIEUsLBR9EBfvIx7qwKVXaWCa\n" +
            "oTiV7iuwwsFScodNb+E2DJJ9Tza+78enjbDQlpuxl682N913GgxuJ7ZKwiRyP6t7\n" +
            "0sIMDVjvqIZkwFA5YOD2rvQaCjt1nBWkjhJLkqH6z+GD7b/bQ+Yv6CuXzMgMNZmm\n" +
            "vXFvCpZ1NHT0dmeHpYee9WwYOJ7sJX6g+nwEepjj17F0iKdJKX+bwjwd8OB/oEDo\n" +
            "QdNeqOFwn/Xwrp+D1BI4pEGCmoSYEaM9Zugh33c87blu1XUijXAOmuzopyzaYjbH\n" +
            "ulN9t3xk+cgmM5gmjIT0/geeErTu9HLffocJeYZbQx2mIYpMkw==\n" +
            "-----END CERTIFICATE-----";

    String phpCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4zCCAsugAwIBAgIJAOyZbqoiynvSMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzAxMDMwMzAxNDRaFw00MjEyMjkwMzAxNDRaMIGF\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xLTArBgNVBAMM\n" +
            "JFByaXZhdGUgS01TIGFwLXNvdXRoZWFzdC02IFNlY29uZCBDQTCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBANIPzzDz6pdAb7Mjyrpo6cyoY5/uJCAufal2\n" +
            "Y4INrWfK7bi4980LlxkgwW45OmtB1JAu4bfYhfaoBkHahYd/vWBM8lZB0JO2kALc\n" +
            "HU5NuSGK6xI8VP/DRg+c+1LZZyT0D06nDAJEB73Z1oszqu0JQArdlwrDSqRI8aCp\n" +
            "k2xKLEbouJDjb7GGfuuODxfQSa/16vp+VnHzVrtGiRHMQNXIqRkKJmfl5PMQaX1I\n" +
            "v6QnvIEqCnaz8G6djnU3+UUh11uwWR9Xq1cbSI8boQ6yhpYhEef/Yuc6X5fr/zeS\n" +
            "Dm9zRoo7Cl+PXnj1qzYQ60ppTfoz6uT4lBHb+ytknMtZrK/GH0sCAwEAAaNmMGQw\n" +
            "HQYDVR0OBBYEFN5DC6SMe/jahZjnbh0YLGA9GuHvMB8GA1UdIwQYMBaAFAVKzUR5\n" +
            "/d6jnYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD\n" +
            "AgGGMA0GCSqGSIb3DQEBCwUAA4IBAQAO1FiHywFGo4GEpuCZcz5wmddx9DHoEh5h\n" +
            "0jkNrhlO6GEsHShO89v9SZkQqfH3vzokHpctU1/LedxHH+MNzwryiTJeczDaNSLK\n" +
            "TmUV/2kOLs+3tOpusQhfCbZAmwhrg9WIhZIh7VV6x2DYNgP03/pU2flx7gcrAbTa\n" +
            "LteY/9PVwDgjXA1kVskQl3nKJP2V+QMVAkK/DsFfn5lHpp2lqiW/OP0JQLDqKXNo\n" +
            "JyCEhscOwjgnvb+n2pcSdg+Y3Z5XG82f9o+ccR9KT+z4Fv2cEH6nfNdjyhhZ6U2k\n" +
            "qJmQwf0mR74IQM63dVDZQm/Ut/J/8JRMUa6exr79n4z++YgNWMZU\n" +
            "-----END CERTIFICATE-----";

    String bjfCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID6TCCAtGgAwIBAgIJAN3DLkKMKyx8MA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yNDA5MjQwNTQyMTJaFw00NDA5MTkwNTQyMTJaMIGL\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xMzAxBgNVBAMM\n" +
            "KlByaXZhdGUgS01TIGNuLWJlaWppbmctZmluYW5jZS0xIFNlY29uZCBDQTCCASIw\n" +
            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ64SKPYaDv5ONDv4BQFLibFdtfx\n" +
            "hSukgcBgSYe19x6bWpsvC8s000MO4xsqei9gCBOF3Stp5oC5ACp0EPhYv9YJt55C\n" +
            "3PLsAuHasub8xuFXOecQCLF5JEyHGa13Anfo1QrZffKO3TiBq1ewWcZhE5VujiiE\n" +
            "0hPNzkt4KfwMoMnzQ3amzHtcQV7S7kZAFe4F0VcrJzupI6IIf6TUp973JcA3msBM\n" +
            "HUOFRKNQHwR7UrRRfJU+AvHVmQJ+5qDmIrfIcLrw0WSE+LYJjB9b0xwzWdfBA89x\n" +
            "pCm+zoqDmdwTo3l+plWclZEqBsReW/OG8Apd9rsAv27vmEuC/9RFFxzVP00CAwEA\n" +
            "AaNmMGQwHQYDVR0OBBYEFIEV1OR3N1PRESXAr1Fb0xuJ6xupMB8GA1UdIwQYMBaA\n" +
            "FAVKzUR5/d6jnYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0P\n" +
            "AQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IBAQBsJFl9sxrpPsVOAyL9O56N6EgH\n" +
            "q9kqBvq/2NzNb+o32ZyCJIEXtaaAFfWqbWC2p7qpTHtvHGEAsx7yJZIbug4HX5yO\n" +
            "iAIdTRrMPItGuETe7BPsspXqS1Xwwi9VGHwAquuYj0ksYBUbFjL8o8Pe9VnqI/Ne\n" +
            "vX+DTR2FZ8+4ZKvGmakEwK6zseCg58lP4QF4fK5M5n0SSczuZAm3PDppdLJfufRa\n" +
            "LQN1pKHJdh2c+aGN4YpQP/91bYnZxhe+XfQMjHqUZ1jjx+BsQJAdghK/XjvgNMWE\n" +
            "O9YyAR09DofF7AUiUIx9bjLFuf9+3wRfOuEzwm1qt56dMX0XyzBGCu63pdJT\n" +
            "-----END CERTIFICATE-----";

    String thaCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4zCCAsugAwIBAgIJAK/S5jYubNBFMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yMzAyMjcwMjI5MDJaFw00MzAyMjIwMjI5MDJaMIGF\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xLTArBgNVBAMM\n" +
            "JFByaXZhdGUgS01TIGFwLXNvdXRoZWFzdC03IFNlY29uZCBDQTCCASIwDQYJKoZI\n" +
            "hvcNAQEBBQADggEPADCCAQoCggEBAKqmjwjsE+453b++FgNpOubcNNM2Kq+Llk99\n" +
            "/hqqYWi84DbNEHaNvzE+9+hwq9q1Um03fPVE1bJnoMoAfBMfWV21R2gR7uEG/YtA\n" +
            "XMCt1MkziRSxIQhFK/XGbg8hQSGMr5OAfKD38j/KKnUgBMmm98IS6EZYQf2AATIs\n" +
            "g+B8FBvd30Xt8dIcgcuYEV/FBRvjMfONmj0KGKXdoPfN9byGtAyF0NGygQQUyGsU\n" +
            "oA1ZIQfIYn6GZz1mxI1p5TgtXekGkJn+LJX7QBuXREhqDKwphVsjQwV1xeF9W7JA\n" +
            "5ReUWwql+Oz5/RB5BAMHQ+Spbhd2fV7XoTVhNkHYRikl/IgTC3MCAwEAAaNmMGQw\n" +
            "HQYDVR0OBBYEFGrJqPN5wrqCYekFv0E93Ut4LFazMB8GA1UdIwQYMBaAFAVKzUR5\n" +
            "/d6jnYM/bHlxURkGhe2EMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD\n" +
            "AgGGMA0GCSqGSIb3DQEBCwUAA4IBAQA1DllCmdOOEdWa6Tz5vuDse0tUD+1MQk2+\n" +
            "Om+s9RqgP5Qwa+TsL+PiJDXRTCy9okZEO3k8XwJjfGJ14k4IJvN7EGKhepfT7TFU\n" +
            "qRWzIS7zzKLcGl39Cr8XXdV2qErqrdYKoyqdIqi5sTt4SO/fVv10Z9ro4Wxb8frr\n" +
            "B3TvE17A8BAPI+7LkUEWpqBnaJJVNwMiMFYgq8hW1desF+k7kJJQrr3P4Z/A3JVG\n" +
            "RYxvHBNW5w82aoCUznLJgw57h5SZpuxhsbl/x1LRCqEisNMCE43u7cdT+/j34nZZ\n" +
            "LgiZhsp4K90E3Cft5Eb4lO593NCViubUjil4tjffdB5i3/xwF4O1\n" +
            "-----END CERTIFICATE-----";

    String hyaCa = "-----BEGIN CERTIFICATE-----\n" +
            "MIID5TCCAs2gAwIBAgIJAPNoG2LyGoLDMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n" +
            "BAYTAkNOMREwDwYDVQQIDAhaaGVKaWFuZzERMA8GA1UEBwwISGFuZ1pob3UxEDAO\n" +
            "BgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjEcMBoGA1UEAwwTUHJpdmF0\n" +
            "ZSBLTVMgUm9vdCBDQTAeFw0yNDA2MTIwODM0NTZaFw00NDA2MDcwODM0NTZaMIGH\n" +
            "MQswCQYDVQQGEwJDTjERMA8GA1UECAwIWmhlSmlhbmcxETAPBgNVBAcMCEhhbmda\n" +
            "aG91MRAwDgYDVQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xLzAtBgNVBAMM\n" +
            "JlByaXZhdGUgS01TIGNuLWhleXVhbi1hY2RyLTEgU2Vjb25kIENBMIIBIjANBgkq\n" +
            "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Is3knuLxGIA8bh9Q89dEoS7idueROug\n" +
            "avOmaxfceoh9VEzfITyIc4w1Gp3OU9qyVClj2Mhz/E+JQU0W6lMWPIKst6Q4oDCS\n" +
            "SxtliMchwkptg4pQGHum8F6S75GZnh151p8g3+zz4sKxuc98NMRv3p6z6CGD/VbD\n" +
            "wjj3ZZWp4peo60nZMCWr+XH8kUufVGXSfQ83dIYbrl2RybG+0wREEnYrs6APbsvy\n" +
            "vdxN9N4zkOUlGq0ItLJr2N8pd5WvNBJLUXE2MILXXs4ApnQQDo8xeMmSQRW82PH/\n" +
            "jkUrRpIUJ3AE0lbEhdLEmu5PYEknmAyNWNGxnipQpEAS2jgAuvh7gQIDAQABo2Yw\n" +
            "ZDAdBgNVHQ4EFgQUQgYD9GaqQUfL/kPa0Wr3j8AO53UwHwYDVR0jBBgwFoAUBUrN\n" +
            "RHn93qOdgz9seXFRGQaF7YQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E\n" +
            "BAMCAYYwDQYJKoZIhvcNAQELBQADggEBADZ6Z8PWNpHXGVZCDqR8fZ97ABA1F2Cp\n" +
            "sVUx+Uezb/S+MeJq6tyq6posrKMypEKu2QnandxBivFJhFVArDyKPpSBWdZp0QR7\n" +
            "ha5n40H8DABtD5y7KNXII/rXY+4Hckz/uW5GFjz9sHrt7+H9y1EXLqCWLngLWGTw\n" +
            "ym6wYN/QfmYO6I+XtyPJnLuS57nASChwITJYYfzNbrnYXOr7tUzgDq8UXENog7g9\n" +
            "3cUJzWQDitXJekFmgyFKmdyj7GLx4HVlRrB/mO5484CYyuT2oKGdXg0Q8SJwmW0c\n" +
            "QdgRhFcoMnwZTjblchmbCyIxlqBLO204Vs8D0032aPL6nB/xXxtPjUo=\n" +
            "-----END CERTIFICATE-----";
    /**
     * 地域ID与对应CA证书的映射表
     */
    Map<String, String> REGION_ID_AND_CA_MAP = createRegionIdAndCaMap();
    String YYYY_MM_DD = "yyyy-MM-dd";

    String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    String END_CERTIFICATE = "-----END CERTIFICATE-----";

    // Certificate type
    String X509_CERTIFICATE_TYPE = "X.509";

    // Date format
    String TIME_ZONE_UTC = "UTC";

    /**
     * 创建一个不可变的地域ID与CA证书映射表
     *
     * @return 地域ID与CA证书的不可变映射表
     */
    static Map<String, String> createRegionIdAndCaMap() {
        Map<String, String> map = new HashMap<>();
        map.put("cn-hangzhou", hzCa);
        map.put("ap-southeast-1", sgpCa);
        map.put("cn-shanghai", shCa);
        map.put("cn-beijing", bjCa);
        map.put("cn-shenzhen", szCa);
        map.put("ap-northeast-1", jpCa);
        map.put("cn-shanghai-finance-1", shfCa);
        map.put("eu-central-1", deCa);
        map.put("cn-hongkong", hkCa);
        map.put("cn-zhangjiakou", zjkCa);
        map.put("cn-qingdao", qdCa);
        map.put("ap-southeast-3", myCa);
        map.put("cn-huhehaote", hhhtCa);
        map.put("us-east-1", usfCa);
        map.put("us-west-1", usvCa);
        map.put("ap-southeast-5", idCa);
        map.put("cn-chengdu", cdCa);
        map.put("eu-west-1", gbCa);
        map.put("cn-heyuan", hyCa);
        map.put("cn-wulanchabu", wlcbCa);
        map.put("cn-guangzhou", gzCa);
        map.put("me-central-1", mecCa);
        map.put("ap-southeast-6", phpCa);
        map.put("cn-beijing-finance-1", bjfCa);
        map.put("ap-southeast-7", thaCa);
        map.put("cn-heyuan-acdr-1", hyaCa);
        map.put("pre-env", preEnvCa);
        return Collections.unmodifiableMap(map);
    }

    /**
     * 获取CA证书的过期时间（UTC格式）
     *
     * @param caContent ca文件内容
     * @return CA证书的过期时间，格式为yyyy-MM-dd UTC
     */
    static String getCaExpirationUtcDate(String caContent) {
        if (caContent == null || caContent.isEmpty()) {
            return null;
        }
        try {
            String certContent = trimCaContent(caContent);
            byte[] certBytes = Base64.getDecoder().decode(certContent);
            CertificateFactory cf = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

            Date expirationDate = cert.getNotAfter();
            SimpleDateFormat sdf = new SimpleDateFormat(YYYY_MM_DD);
            sdf.setTimeZone(TimeZone.getTimeZone(TIME_ZONE_UTC));
            return sdf.format(expirationDate);
        } catch (Exception e) {
            return null;
        }
    }

    static String trimCaContent(String caContent) {
        String lastCertContent = caContent;
        int lastBeginIndex = caContent.lastIndexOf(BEGIN_CERTIFICATE);
        if (lastBeginIndex > 0) {
            lastCertContent = caContent.substring(lastBeginIndex);
        }
        return lastCertContent.replace(BEGIN_CERTIFICATE, "")
                .replace(END_CERTIFICATE, "")
                .replaceAll("\\s", "");
    }

}
