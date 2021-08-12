package hotp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/yeqown/go-qrcode"
)

type Auth struct{
	Label 	string
	User 		string
	Key 		string 
	Digits 	int
	Period 	int64
}

func GenerateAuthQR(auth Auth, w io.Writer) error{
	url := GenerateURL(auth) 
	return GenerateQR(url, w)
}

func GenerateURL(auth Auth) string{
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		auth.Label,
		auth.User,
		auth.Key,
		auth.Label,
		auth.Digits,
		auth.Period,
	)
}

//GenerateAQR from string message
func GenerateQR(message string, w io.Writer) error{
	qrc, err := qrcode.New(message)
	if err != nil{
		return err
	}

	return qrc.SaveTo(w)
}

//GetTOTPToken return a token using the RFC 4226 system
//and interval usint the unix time from the server
func GetTOTPToken(auth Auth) (string, error){
	interval := time.Now().Unix() / auth.Period
	return GetHOTPToken(auth, interval)
}

//GetHOTPToken return a token using the RFC 4226 system
//Interval is int64 seconds
func GetHOTPToken(auth Auth, interval int64) (string, error) {
	if len(auth.Key) != 16{
		return "", fmt.Errorf("key need to be 16 digit len but get a %d len", len(auth.Key))
	}
	//convert message to [A-Z]
	message := strings.ToUpper(auth.Key)

	//Encode the message
	key, err := base32.StdEncoding.DecodeString(message)

	//Check errors
	if err != nil{
		return "", err
	}

	bs := make([]byte,8)
	binary.BigEndian.PutUint64(bs, uint64(interval))

	//Sign the value
	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	h := hash.Sum(nil)

	o := (h[19] & 15)

	var header uint32

	reader := bytes.NewReader(h[o : o+4])
	err = binary.Read(reader, binary.BigEndian, &header)

	//Check errors
	if err != nil{
		return "", err
	}

	h12 := (int(header) & 0x7fffffff) % 1000000

	otp := strconv.Itoa(int(h12))

	return normalizeOTP(otp, auth.Digits), nil
}

//Check if the length is 6, or add extra zeros
func normalizeOTP(otp string, lenght int) string{
	if len(otp) == int(lenght){
		return otp
	}

	for i := (int(lenght) - len(otp)); i > 0; i--{
		otp = "0" + otp
	}
	return otp
}