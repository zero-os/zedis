package itsyouonline

import (
	"gopkg.in/validator.v2"
)

type Ownerof struct {
	Emailaddresses []EmailAddress `json:"emailaddresses" validate:"nonzero"`
}

func (s Ownerof) Validate() error {

	return validator.Validate(s)
}
