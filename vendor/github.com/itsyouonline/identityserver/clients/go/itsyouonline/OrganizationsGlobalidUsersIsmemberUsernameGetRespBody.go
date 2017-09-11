package itsyouonline

import (
	"gopkg.in/validator.v2"
)

type OrganizationsGlobalidUsersIsmemberUsernameGetRespBody struct {
	IsMember bool `json:"IsMember"`
}

func (s OrganizationsGlobalidUsersIsmemberUsernameGetRespBody) Validate() error {

	return validator.Validate(s)
}
