package models

type User struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	FullName     string `json:"full_name"`
	JobTitle     string `json:"job_title"`
	Organization string `json:"organization"`
	Timezone     string `json:"timezone"`
	Bio          string `json:"bio"`
	RoleLabel    string `json:"role_label"`
}
