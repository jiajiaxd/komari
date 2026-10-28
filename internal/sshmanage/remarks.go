package sshmanage

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"gorm.io/gorm/clause"
)

func ListRemarks() (map[string]string, error) {
	var rows []models.SSHKeyRemark
	if err := dbcore.GetDBInstance().Find(&rows).Error; err != nil {
		return nil, err
	}
	remarks := make(map[string]string, len(rows))
	for _, row := range rows {
		remarks[row.Fingerprint] = row.Remark
	}
	return remarks, nil
}

// NormalizeRemark validates panel metadata without changing authorized_keys.
func NormalizeRemark(fingerprint, remark string) (string, string, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	digest, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(fingerprint, "SHA256:"))
	if err != nil || !strings.HasPrefix(fingerprint, "SHA256:") || len(digest) != 32 {
		return "", "", errors.New("invalid SHA256 key fingerprint")
	}
	remark = strings.TrimSpace(remark)
	if !utf8.ValidString(remark) || utf8.RuneCountInString(remark) > 200 || strings.ContainsFunc(remark, unicode.IsControl) {
		return "", "", errors.New("remark must be a single line of at most 200 characters")
	}
	return fingerprint, remark, nil
}

// SetRemark persists a normalized remark. Empty restores the agent's comment.
func SetRemark(fingerprint, remark string) error {
	db := dbcore.GetDBInstance()
	if remark == "" {
		return db.Where("fingerprint = ?", fingerprint).Delete(&models.SSHKeyRemark{}).Error
	}
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "fingerprint"}},
		DoUpdates: clause.AssignmentColumns([]string{"remark"}),
	}).Create(&models.SSHKeyRemark{Fingerprint: fingerprint, Remark: remark}).Error
}
