package smb

import (
	"errors"
	"fmt"
	"github.com/hirochachacha/go-smb2"
	log "github.com/sirupsen/logrus"
	"net"
	"net/url"
	"os"
	"os/user"
	"strings"
)

type Service struct {
	Url          string
	Host         string
	Port         string
	User         string
	Password     string
	Domain       string
	ShareName    string
	FilePath     string
	FileContents []byte
}

func NewSambaService(url string) Service {
	return Service{
		Url: url,
	}
}

func (s *Service) Fetch() error {
	if err := s.ParseUrl(); err != nil {
		return err
	}
	return s.FetchFile()
}

func (s *Service) FetchFile() error {

	pwdOutput := "***"
	if s.Password == "" {
		pwdOutput = "none"
	}
	// by usage, this method is called before log leve is set
	// so Debugf statement here is not effective
	log.Infof("fetching remote file server: %s:%s, user: %s, pwd: %s, domain: %s, share: %s, path: %s",
		s.Host, s.Port, s.User, pwdOutput, s.Domain, s.ShareName, s.FilePath)

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", s.Host, s.Port))
	if err != nil {
		return err
	}
	defer func(conn net.Conn) {
		err = conn.Close()
	}(conn)

	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     s.User,
			Password: s.Password,
			Domain:   s.Domain,
		},
	}

	session, err := dialer.Dial(conn)
	if err != nil {
		return err
	}
	defer func(session *smb2.Session) {
		err = session.Logoff()
	}(session)

	fs, err := session.Mount(s.ShareName)
	if err != nil {
		return err
	}
	defer func(fs *smb2.Share) {
		err = fs.Umount()
	}(fs)

	s.FileContents, err = fs.ReadFile(s.FilePath)
	return err
}

// ParseUrl - parses according to https://www.iana.org/assignments/uri-schemes/prov/smb
// except for the query string
// smb://[[<domain>;]<username>[:<password>]@]<server>[:<port>][/[<share>[/[<path>]]][?[<param>=<value>[;<param2>=<value2>[...]]]]]
func (s *Service) ParseUrl() error {
	u, err := url.Parse(s.Url)
	if err != nil {
		return err
	}

	if u.Scheme != "smb" {
		return errors.New("invalid scheme")
	}
	s.Host = u.Hostname()
	if s.Host == "" {
		return errors.New("missing hostname")
	}
	s.Port = u.Port()
	if s.Port == "" {
		s.Port = "445"
	}

	splits := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(splits) < 2 {
		return errors.New("invalid path spec, expecting shareName and filePath to be included: " + u.Path)
	}

	s.ShareName = splits[0]
	s.FilePath = strings.Join(splits[1:], "/")

	// smb url spec allows for domain in front of user with a semicolon
	splits = strings.Split(u.User.Username(), ";")
	if len(splits) == 1 {
		s.User = splits[0]
	} else if len(splits) == 2 {
		s.Domain = splits[0]
		s.User = splits[1]
	}

	if s.User == "" {
		curUser, err := user.Current()
		if err != nil {
			return err
		}
		s.User = curUser.Username
	}
	if s.User == "root" {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			s.User = sudoUser
		}
	}

	s.Password, _ = u.User.Password()
	if s.Password == "*" {
		fmt.Println("Please enter smb password: ")
		_, err := fmt.Scanln(&s.Password)
		if err != nil {
			return err
		}
	}

	return nil
}
