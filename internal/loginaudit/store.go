package loginaudit

import (
	"time"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	logger "github.com/komari-monitor/komari/utils/log"
)

// ListOptions 登录记录查询条件
type ListOptions struct {
	Limit         int
	Page          int
	ClientUUID    string
	UntrustedOnly bool
}

// List 按登录时间倒序分页查询登录记录。
func List(opts ListOptions) ([]models.LoginRecord, int64, error) {
	db := dbcore.GetDBInstance().Model(&models.LoginRecord{})
	if opts.ClientUUID != "" {
		db = db.Where("client_uuid = ?", opts.ClientUUID)
	}
	if opts.UntrustedOnly {
		db = db.Where("trusted = ?", false)
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	records := make([]models.LoginRecord, 0, opts.Limit)
	err := db.Order("login_time desc").Order("id desc").
		Limit(opts.Limit).Offset((opts.Page - 1) * opts.Limit).
		Find(&records).Error
	return records, total, err
}

// Clear 删除全部登录记录，clientUUID 非空时只删除该节点的记录。
func Clear(clientUUID string) (int64, error) {
	db := dbcore.GetDBInstance()
	if clientUUID != "" {
		db = db.Where("client_uuid = ?", clientUUID)
	} else {
		db = db.Where("1 = 1")
	}
	res := db.Delete(&models.LoginRecord{})
	return res.RowsAffected, res.Error
}

// Cleanup 按保留天数与最大条数清理登录记录，由定时任务调用。
func Cleanup() {
	cfg, err := loadSettings()
	if err != nil {
		logger.Error("loginaudit", "failed to load settings", "error", err)
		return
	}
	if err := cleanup(cfg.RetentionDays, cfg.MaxRecords, time.Now().UTC()); err != nil {
		logger.Error("loginaudit", "failed to clean login records", "error", err)
	}
}

func cleanup(retentionDays, maxRecords int, now time.Time) error {
	db := dbcore.GetDBInstance()
	if retentionDays > 0 {
		threshold := now.AddDate(0, 0, -retentionDays)
		if err := db.Where("login_time < ?", threshold).Delete(&models.LoginRecord{}).Error; err != nil {
			return err
		}
	}
	if maxRecords <= 0 {
		return nil
	}
	// 找到按登录时间排序后第 maxRecords+1 条及之后的记录并删除
	var ids []uint
	if err := db.Model(&models.LoginRecord{}).
		Order("login_time desc").Order("id desc").
		Offset(maxRecords).Limit(-1).
		Pluck("id", &ids).Error; err != nil {
		return err
	}
	for start := 0; start < len(ids); start += 500 {
		end := min(start+500, len(ids))
		if err := db.Where("id IN ?", ids[start:end]).Delete(&models.LoginRecord{}).Error; err != nil {
			return err
		}
	}
	return nil
}
