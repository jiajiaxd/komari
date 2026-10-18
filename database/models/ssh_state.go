package models

import "time"

// SSHState 缓存 agent 最近一次上报的 root SSH 登录配置（公钥、端口、root 密码登录）。
type SSHState struct {
	ClientUUID string     `json:"client_uuid" gorm:"type:varchar(36);primaryKey"`
	State      string     `json:"-" gorm:"type:text"` // v2.SSHState 的 JSON
	StateAt    *time.Time `json:"state_at"`           // State 的采集时间
	Error      string     `json:"error" gorm:"type:text"`
	CheckedAt  time.Time  `json:"checked_at"` // 最近一次请求 agent 的时间
}
