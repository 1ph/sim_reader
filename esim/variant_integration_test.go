package esim

import (
	"embed"
	"encoding/json"
	"strings"
	"testing"

	"sim_reader/sim"
)

//go:embed testdata/variant3/*.txt testdata/variant3/*.json
var variant3FS embed.FS

func TestVariant3NoAppletProfile(t *testing.T) {
	// 1. Загрузка шаблона из встроенных данных
	templateData, err := variant3FS.ReadFile("testdata/variant3/template.txt")
	if err != nil {
		t.Fatalf("failed to read template: %v", err)
	}

	template, err := ParseValueNotation(string(templateData))
	if err != nil {
		t.Fatalf("failed to parse template: %v", err)
	}

	// 2. Загрузка конфигурации из встроенных данных
	configData, err := variant3FS.ReadFile("testdata/variant3/config.json")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	var config sim.SIMConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	// 3. Создание профиля
	profile, err := BuildProfileFromSIMConfig(template, &config)
	if err != nil {
		t.Fatalf("failed to build profile: %v", err)
	}

	// Делаем round-trip через DER, чтобы получить то же состояние, что и при экспорте из файла.
	// Это важно, так как при декодировании DER заполняются значения по умолчанию (например, для AKA параметров).
	profileBytes, err := EncodeProfile(profile)
	if err != nil {
		t.Fatalf("failed to encode profile: %v", err)
	}
	profile, err = DecodeProfile(profileBytes)
	if err != nil {
		t.Fatalf("failed to decode profile: %v", err)
	}

	// Проверка базовых параметров в созданном профиле
	if profile.GetICCID() != config.ICCID {
		t.Errorf("ICCID mismatch: got %s, want %s", profile.GetICCID(), config.ICCID)
	}
	if profile.GetIMSI() != config.IMSI {
		t.Errorf("IMSI mismatch: got %s, want %s", profile.GetIMSI(), config.IMSI)
	}
	if profile.GetProfileType() != config.ProfileType {
		t.Errorf("ProfileType mismatch: got %s, want %s", profile.GetProfileType(), config.ProfileType)
	}

	// Проверка PIN1
	if profile.GetPIN1() != config.PIN1 {
		t.Errorf("PIN1 mismatch: got %s, want %s", profile.GetPIN1(), config.PIN1)
	}
	// Проверка PUK1
	if profile.GetPUK1() != config.PUK1 {
		t.Errorf("PUK1 mismatch: got %s, want %s", profile.GetPUK1(), config.PUK1)
	}
	// Проверка ADM1
	if profile.GetADM1() != config.ADM1 {
		t.Errorf("ADM1 mismatch: got %s, want %s", profile.GetADM1(), config.ADM1)
	}

	// 4. Экспорт профиля в текстовый формат и сравнение с эталоном
	expectedData, err := variant3FS.ReadFile("testdata/variant3/expected.txt")
	if err != nil {
		t.Fatalf("failed to read expected output: %v", err)
	}

	actualNotation := GenerateValueNotation(profile)
	expectedNotation := string(expectedData)

	// Сравниваем, игнорируя различия в пробелах и пустых строках для надежности
	actualNormalized := normalizeNotation(actualNotation)
	expectedNormalized := normalizeNotation(expectedNotation)
	if actualNormalized != expectedNormalized {
		// Если не совпало, выводим разницу (для краткости в тесте можно просто ошибку)
		t.Errorf("exported notation mismatch")

		// Находим первую различающуюся строку для отладки
		actualLines := strings.Split(actualNormalized, "\n")
		expectedLines := strings.Split(expectedNormalized, "\n")
		for i := 0; i < len(actualLines) && i < len(expectedLines); i++ {
			if actualLines[i] != expectedLines[i] {
				t.Errorf("first mismatch at normalized line %d:\ngot:  %s\nwant: %s", i+1, actualLines[i], expectedLines[i])
				break
			}
		}
	}
}

// normalizeNotation удаляет лишние пробелы и пустые строки для сравнения
func normalizeNotation(s string) string {
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return strings.Join(result, "\n")
}

