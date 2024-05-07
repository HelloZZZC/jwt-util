package util

import (
	"errors"
	"github.com/golang-jwt/jwt/v4"
)

type JwtUtil struct {
	secret string
}

// GenToken gen jwt token for subject
func (j JwtUtil) GenToken(subjectId string) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject: subjectId,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(j.secret)

	return ss, err
}

// Parse verify token valid
func (j JwtUtil) Parse(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (i interface{},
		err error) {
		return j.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
