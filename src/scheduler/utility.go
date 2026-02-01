package scheduler

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
)

func StructMapToJSON[T any](data []T) (string, error) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		err_msg := fmt.Errorf("failed to marshal data: %w", err)
		return "", err_msg
	}
	return string(jsonData), nil
}

func StructsToJSONFile[T any](data []T, filename string) error {
	jsonData, err := StructMapToJSON(data)
	if err != nil {
		return err
	}
	err = os.WriteFile(filename, []byte(jsonData), 0644)
	if err != nil {
		err_msg := fmt.Errorf("failed to write data to file: %w", err)
		return err_msg
	}
	return nil
}

// StructsToCSVFile 将带JSON标签的结构体切片序列化为指定的CSV文件
// 泛型约束：T为任意结构体类型（支持结构体/结构体指针切片）
// 参数说明：
//
//	filepath: 目标JSON文件的完整路径（文件所在目录已提前创建，如 "mtsas/result.json"）
//	data: 带JSON标签的结构体切片（核心数据）
//
// 返回值：执行错误（nil表示成功）

// StructsToCSVFile 将结构体切片写入CSV文件，支持嵌套结构体的扁平化
func StructsToCSVFile[T any](data []T, filePath string) error {
	if len(data) == 0 {
		return nil
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 获取扁平化后的表头
	headers, fieldAccessors := getFlatHeaders(data[0])
	if err := writer.Write(headers); err != nil {
		return err
	}

	// 写入数据行
	for _, item := range data {
		v := reflect.ValueOf(item)
		var row []string
		for _, accessor := range fieldAccessors {
			fieldValue := accessor.getFieldValue(v)
			strVal := convertToString(fieldValue)
			row = append(row, strVal)
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// fieldAccessor 用于记录如何访问扁平化后的字段
type fieldAccessor struct {
	indices []int // 字段的索引路径
}

func (fa fieldAccessor) getFieldValue(v reflect.Value) reflect.Value {
	for _, index := range fa.indices {
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return reflect.Value{}
			}
			v = v.Elem()
		}
		v = v.Field(index)
	}
	return v
}

// getFlatHeaders 获取扁平化后的表头和字段访问路径
func getFlatHeaders(sample any) ([]string, []fieldAccessor) {
	t := reflect.TypeOf(sample)
	var headers []string
	var accessors []fieldAccessor

	var traverse func(t reflect.Type, parentIndices []int, parentJSONPath string)
	traverse = func(t reflect.Type, parentIndices []int, parentJSONPath string) {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			jsonTag := field.Tag.Get("json")
			if jsonTag == "" || jsonTag == "-" {
				continue
			}
			jsonName := strings.Split(jsonTag, ",")[0]
			if jsonName == "" {
				continue
			}

			currentJSONPath := parentJSONPath
			if currentJSONPath != "" {
				currentJSONPath += "."
			}
			currentJSONPath += jsonName

			currentIndices := make([]int, len(parentIndices))
			copy(currentIndices, parentIndices)
			currentIndices = append(currentIndices, i)

			// 判断是否为需要扁平化的嵌套结构体（非时间等内置类型）
			fieldType := field.Type
			if fieldType.Kind() == reflect.Ptr {
				fieldType = fieldType.Elem()
			}

			if fieldType.Kind() == reflect.Struct && !isBuiltinType(fieldType) {
				traverse(fieldType, currentIndices, currentJSONPath)
			} else {
				headers = append(headers, currentJSONPath)
				accessors = append(accessors, fieldAccessor{indices: currentIndices})
			}
		}
	}

	traverse(t, []int{}, "")
	return headers, accessors
}

// isBuiltinType 判断是否为需要跳过的内置结构体类型（如time.Time）
func isBuiltinType(t reflect.Type) bool {
	return t.PkgPath() == "time" && t.Name() == "Time"
}

// convertToString 将反射值转换为字符串
func convertToString(v reflect.Value) string {
	if !v.IsValid() {
		return ""
	}
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'f', -1, 64)
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	default:
		if jsonBytes, err := json.Marshal(v.Interface()); err == nil {
			return string(jsonBytes)
		}
		return v.String()
	}
}

func WriteToFile[T any](outputFormat string, data []T, filename string) error {
	switch outputFormat {
	case "json":
		return StructsToJSONFile(data, filename)
	case "csv":
		return StructsToCSVFile(data, filename)
	case "":
		return nil
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
}
