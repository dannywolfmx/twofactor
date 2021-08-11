package hotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetHOTPToken(t *testing.T) {
	//Secret message and duration

	message := "dummySECRETdummy"
	intervalInSeconds := int64(30)
	unixTime := int64(1628726047)
	duration := unixTime / intervalInSeconds
	expectedResult := "427727"

	result, err := getHOTPToken(message, duration) 

	assert.NoError(t, err)
	assert.Equal(t,len(expectedResult), len(result))
	assert.Equal(t,expectedResult, result)
}

func TestNormalizeOTP(t *testing.T){

	//Input - ExpectedOutput
	testData := map[string]string{
		"1":"000001",
		"11":"000011",
		"111":"000111",
		"1111":"001111",
		"11111":"011111",
		"111111":"111111",
	}


	for key, value := range testData{
		result := normalizeOTP(key)
		assert.Equal(t, value, result)
	}
}