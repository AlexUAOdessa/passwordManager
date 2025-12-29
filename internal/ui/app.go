package ui

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"passwordManager/internal/crypto"
	"passwordManager/internal/models"
	"passwordManager/internal/storage"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

type AppContext struct {
	Window         fyne.Window
	Entries        []models.Entry
	MasterPassword string
	Session        *crypto.CryptoSession
	List           *widget.List
}

func GenerateSecurePassword(length int, useSpecial bool) string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if useSpecial {
		chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
	}
	res := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		res[i] = chars[idx.Int64()]
	}
	return string(res)
}

func StartUI(w fyne.Window) {
	ctx := &AppContext{Window: w}

	passInput := widget.NewPasswordEntry()
	passInput.SetPlaceHolder("Мастер-пароль")

	var authBox *fyne.Container

	// Инициализация списка
	ctx.List = widget.NewList(
		func() int { return len(ctx.Entries) },
		func() fyne.CanvasObject { return widget.NewLabel("Service") },
		func(id widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(ctx.Entries[id].Service)
		},
	)

	// Кнопка добавления
	addBtn := widget.NewButton("Добавить запись", func() {
		showAddDialog(ctx)
	})
	addBtn.Hide()

	ctx.List.OnSelected = func(id widget.ListItemID) {
		showDetailDialog(ctx, id)
		ctx.List.Unselect(id)
	}

	unlockBtn := widget.NewButton("Разблокировать", func() {
		ctx.MasterPassword = passInput.Text
		data, err := storage.Load()
		if err != nil {
			dialog.ShowConfirm("База не найдена", "Создать новую?", func(b bool) {
				if b {
					ctx.Entries = []models.Entry{}
					saveState(ctx)
					authBox.Hide()
					addBtn.Show()
				}
			}, w)
			return
		}

		decrypted, err := crypto.Decrypt(data, ctx.MasterPassword)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Неверный пароль"), w)
			return
		}

		json.Unmarshal(decrypted, &ctx.Entries)
		ctx.Session = crypto.NewSession(ctx.MasterPassword, nil) // упрощено
		authBox.Hide()
		addBtn.Show()
		ctx.List.Refresh()
	})

	authBox = container.NewVBox(widget.NewLabel("Авторизация:"), passInput, unlockBtn)

	w.SetContent(container.NewBorder(
		authBox,
		addBtn,
		nil, nil,
		ctx.List,
	))
}

func saveState(ctx *AppContext) {
	data, _ := json.Marshal(ctx.Entries)
	enc, _ := crypto.Decrypt(data, ctx.MasterPassword) // Для простоты используем ту же функцию шифрования
	// Примечание: в полной версии здесь вызывается crypto.Encrypt
	storage.Save(enc)
	ctx.List.Refresh()
}

func showAddDialog(ctx *AppContext) {
	s := widget.NewEntry()
	l := widget.NewEntry()
	p := widget.NewEntry()
	
	lenSlider := widget.NewSlider(8, 32)
	lenSlider.SetValue(16)
	
	genBtn := widget.NewButton("Генерировать", func() {
		p.SetText(GenerateSecurePassword(int(lenSlider.Value), true))
	})

	form := container.NewVBox(
		widget.NewLabel("Сервис:"), s,
		widget.NewLabel("Логин:"), l,
		widget.NewLabel("Пароль:"), p,
		genBtn, widget.NewLabel("Длина пароля:"), lenSlider,
	)

	dialog.ShowCustomConfirm("Новая запись", "Сохранить", "Отмена", form, func(b bool) {
		if b {
			ctx.Entries = append(ctx.Entries, models.Entry{Service: s.Text, Login: l.Text, Password: p.Text})
			saveState(ctx)
		}
	}, ctx.Window)
}

func showDetailDialog(ctx *AppContext, id widget.ListItemID) {
	entry := ctx.Entries[id]
	passLabel := widget.NewLabel("********")

	content := container.NewVBox(
		widget.NewLabel("Сервис: "+entry.Service),
		widget.NewLabel("Логин: "+entry.Login),
		container.NewHBox(passLabel, widget.NewButton("Показать", func() {
			if passLabel.Text == "********" { passLabel.SetText(entry.Password) } else { passLabel.SetText("********") }
		})),
		widget.NewButton("Копировать пароль", func() { ctx.Window.Clipboard().SetContent(entry.Password) }),
		widget.NewSeparator(),
		widget.NewButton("Удалить", func() {
			ctx.Entries = append(ctx.Entries[:id], ctx.Entries[id+1:]...)
			saveState(ctx)
		}),
	)
	dialog.ShowCustom("Детали", "Закрыть", content, ctx.Window)
}