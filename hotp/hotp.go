package hotp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

//getTOTPToken return a token using the RFC 4226 system
//and interval usint the unix time from the server
func GetTOTPToken(message string) (string, error){
	interval := time.Now().Unix() / 30
	return GetHOTPToken(message, interval)
}

//getHOTPToken return a token using the RFC 4226 system
//Interval is int64 seconds
func GetHOTPToken(message string, interval int64) (string, error) {
	if len(message) != 16{
		return "", fmt.Errorf("message need to be 16 digit len but get a %d len", len(message))
	}
	//convert message to [A-Z]
	message = strings.ToUpper(message)

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

	return normalizeOTP(otp), nil
}

//Check if the length is 6, or add extra zeros
func normalizeOTP(otp string) string{
	if len(otp) == 6{
		return otp
	}

	for i := (6 - len(otp)); i > 0; i--{
		otp = "0" + otp
	}
	return otp
}