module rpc

go 1.20

// uncomment if developing with go-wsman-messages locally
// replace github.com/open-amt-cloud-toolkit/go-wsman-messages/v2 => ../go-wsman-messages

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/hirochachacha/go-smb2 v1.1.0
	github.com/ilyakaznacheev/cleanenv v1.5.0
	github.com/open-amt-cloud-toolkit/go-wsman-messages/v2 v2.8.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	golang.org/x/sys v0.21.0
)

require (
	github.com/geoffgarside/ber v1.1.0 // indirect
	golang.org/x/crypto v0.21.0 // indirect
)

require (
	github.com/BurntSushi/toml v1.2.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/term v0.21.0
	gopkg.in/yaml.v3 v3.0.1
	olympos.io/encoding/edn v0.0.0-20201019073823-d3554ca0b0a3 // indirect
	software.sslmate.com/src/go-pkcs12 v0.4.0
)
