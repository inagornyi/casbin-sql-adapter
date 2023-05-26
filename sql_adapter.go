package sqladapter

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
)

type CasbinRule struct {
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

type SQLAdapter struct {
	db        *sql.DB
	tableName string
}

func NewSQLAdapter(driverName, user, password, url, databaseName, tableName string) (*SQLAdapter, error) {
	db, err := sql.Open(driverName, fmt.Sprintf("%s:%s@tcp(%s)/%s", user, password, url, databaseName))
	if err != nil {
		return nil, err
	}
	return &SQLAdapter{
		db:        db,
		tableName: tableName,
	}, nil
}

func (a *SQLAdapter) SavePolicy(model model.Model) error {
	return a.WithTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`INSERT INTO ` + a.tableName + ` (ptype, v0, v1, v2, v3, v4, v5) 
                                 VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for ptype, ast := range model["p"] {
			for _, rule := range ast.Policy {
				line := savePolicyLine(ptype, rule)
				if _, err := stmt.Exec(line.PType, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5); err != nil {
					tx.Rollback()
					return err
				}
			}
		}

		for ptype, ast := range model["g"] {
			for _, rule := range ast.Policy {
				line := savePolicyLine(ptype, rule)
				if _, err := stmt.Exec(line.PType, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5); err != nil {
					tx.Rollback()
					return err
				}
			}
		}

		return nil
	})

}

func (a *SQLAdapter) LoadPolicy(model model.Model) error {
	return a.WithTx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT ptype, v0, v1, v2, v3, v4, v5 FROM ` + a.tableName)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var ptype, v0, v1, v2, v3, v4, v5 string
			if err := rows.Scan(&ptype, &v0, &v1, &v2, &v3, &v4, &v5); err != nil {
				return err
			}

			var p = []string{ptype, v0, v1, v2, v3, v4, v5}

			var lineText string
			if v5 != "" {
				lineText = strings.Join(p, ", ")
			} else if v4 != "" {
				lineText = strings.Join(p[:6], ", ")
			} else if v3 != "" {
				lineText = strings.Join(p[:5], ", ")
			} else if v2 != "" {
				lineText = strings.Join(p[:4], ", ")
			} else if v1 != "" {
				lineText = strings.Join(p[:3], ", ")
			} else if v0 != "" {
				lineText = strings.Join(p[:2], ", ")
			}

			persist.LoadPolicyLine(lineText, model)
		}

		if err := rows.Err(); err != nil {
			return err
		}

		return nil
	})
}

func (a *SQLAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.WithTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`INSERT INTO ` + a.tableName + ` (ptype, v0, v1, v2, v3, v4, v5) 
                                 VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		line := savePolicyLine(ptype, rule)
		if _, err := stmt.Exec(line.PType, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5); err != nil {
			return err
		}

		return nil
	})
}

func (a *SQLAdapter) AddPolicies(sec, ptype string, rules [][]string) error {
	return a.WithTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`INSERT INTO ` + a.tableName + ` (ptype, v0, v1, v2, v3, v4, v5)
							     VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, rule := range rules {
			line := savePolicyLine(ptype, rule)
			_, err = stmt.Exec(ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func (a *SQLAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.WithTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`DELETE FROM ` + a.tableName + ` WHERE ptype = ? AND v0 = ? 
                                 AND v1 = ? AND v2 = ? AND v3 = ? AND v4 = ? AND v5 = ?`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		line := savePolicyLine(ptype, rule)
		if _, err := stmt.Exec(line.PType, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5); err != nil {
			return err
		}

		return nil
	})
}

func (a *SQLAdapter) RemovePolicies(sec, ptype string, rules [][]string) error {
	return a.WithTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`DELETE FROM ` + a.tableName + ` WHERE ptype = ? AND v0 = ? AND v1 = ? AND v2 = ? AND v3 = ? AND v4 = ? AND v5 = ?`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, rule := range rules {
			line := savePolicyLine(ptype, rule)
			if _, err := stmt.Exec(line.PType, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5); err != nil {
				if err != nil {
					return err
				}
			}

		}

		return nil
	})
}

func (a *SQLAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.WithTx(func(tx *sql.Tx) error {
		condition := make([]string, 6)
		for i := range condition {
			if fieldIndex+i < len(fieldValues) {
				condition[i] = fmt.Sprintf("v%d = ?", i)
			} else {
				condition[i] = "1=1"
			}
		}

		query := fmt.Sprintf(`DELETE FROM %s WHERE ptype = ? AND %s`, a.tableName, strings.Join(condition, ` AND `))

		stmt, err := tx.Prepare(query)
		if err != nil {
			return err
		}
		defer stmt.Close()

		args := make([]interface{}, 0, len(fieldValues)+1)
		args = append(args, ptype)
		for _, v := range fieldValues {
			args = append(args, v)
		}
		if _, err := stmt.Exec(args...); err != nil {
			return err
		}

		return nil
	})
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{}

	line.PType = ptype

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

func (a *SQLAdapter) WithTx(fn func(tx *sql.Tx) error) error {
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if v := recover(); v != nil {
			if err := tx.Rollback(); err != nil {
				fmt.Printf("rolling back transaction: %v", err)
			}
		}
	}()
	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			err = errors.Wrapf(err, "rolling back transaction: %v", rerr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrapf(err, "committing transaction: %v", err)
	}
	return nil
}
