package models

// SSHKeyRemark names a public key across nodes, independently of agent snapshots.
type SSHKeyRemark struct {
	Fingerprint string `gorm:"type:varchar(50);primaryKey"`
	Remark      string `gorm:"type:text;not null"`
}
