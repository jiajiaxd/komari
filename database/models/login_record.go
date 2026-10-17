package models

import "time"

// LoginRecord 是 agent 上报的一次 SSH/RDP 成功登录及其来源分析结果。
type LoginRecord struct {
	ID          uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	ClientUUID  string    `json:"client_uuid" gorm:"type:varchar(36);index:idx_login_records_client"`
	ClientName  string    `json:"client_name" gorm:"type:varchar(100)"`
	Protocol    string    `json:"protocol" gorm:"type:varchar(10)"` // ssh / rdp
	Username    string    `json:"username" gorm:"type:varchar(255)"`
	SourceIP    string    `json:"source_ip" gorm:"type:varchar(45)"`
	SourcePort  int       `json:"source_port"`
	AuthMethod  string    `json:"auth_method" gorm:"type:varchar(64)"`
	Country     string    `json:"country" gorm:"type:varchar(100)"`
	CountryCode string    `json:"country_code" gorm:"type:varchar(8)"`
	Region      string    `json:"region" gorm:"type:varchar(100)"`
	RegionCode  string    `json:"region_code" gorm:"type:varchar(16)"`
	City        string    `json:"city" gorm:"type:varchar(100)"`
	ISP         string    `json:"isp" gorm:"type:varchar(255)"`
	Trusted     bool      `json:"trusted"`
	TrustReason string    `json:"trust_reason" gorm:"type:varchar(16)"` // private / server / whitelist / region
	Alerted     bool      `json:"alerted"`
	LoginTime   time.Time `json:"login_time" gorm:"not null;index:idx_login_records_time"`
	CreatedAt   time.Time `json:"created_at" gorm:"autoCreateTime"`
}
