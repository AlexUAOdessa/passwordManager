package ui

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"math/big"
	"os"
	"passwordManager/internal/crypto"
	"passwordManager/internal/models"
	"passwordManager/internal/storage"
	"sort"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

type AppContext struct {
	Window         fyne.Window
	Entries        []models.Entry
	MasterPassword string
	Session        *crypto.CryptoSession
	CurrentSalt    []byte // Соль текущей открытой базы
	List           *widget.List
}

// RightClickContainer корректно реализует перехват событий мыши без блокировки вложенных элементов
type RightClickContainer struct {
	widget.BaseWidget
	content      fyne.CanvasObject
	OnRightClick func(*desktop.MouseEvent)
}

func NewRightClickContainer(content fyne.CanvasObject, callback func(*desktop.MouseEvent)) *RightClickContainer {
	res := &RightClickContainer{
		content:      content,
		OnRightClick: callback,
	}
	res.ExtendBaseWidget(res)
	return res
}

func (c *RightClickContainer) CreateRenderer() fyne.WidgetRenderer {
	// Используем простой рендерер, который отображает вложенный список
	return widget.NewSimpleRenderer(c.content)
}

func (c *RightClickContainer) MouseDown(ev *desktop.MouseEvent) {
	if ev.Button == desktop.MouseButtonSecondary && c.OnRightClick != nil {
		c.OnRightClick(ev)
	}
}

func (c *RightClickContainer) MouseUp(*desktop.MouseEvent)   {}
func (c *RightClickContainer) MouseMoved(*desktop.MouseEvent) {}
func (c *RightClickContainer) MouseIn(*desktop.MouseEvent)    {}
func (c *RightClickContainer) MouseOut()                      {}

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

func sortEntries(entries []models.Entry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Group != entries[j].Group {
			return entries[i].Group < entries[j].Group
		}
		return entries[i].Service < entries[j].Service
	})
}

func StartUI(w fyne.Window) {
	ctx := &AppContext{Window: w}
	passInput := widget.NewPasswordEntry()
	passInput.SetPlaceHolder("Мастер-пароль")

	var authBox *fyne.Container
	var mainView *fyne.Container

	ctx.List = widget.NewList(
		func() int {
			count := 0
			for _, e := range ctx.Entries {
				if !e.IsDeleted {
					count++
				}
			}
			return count
		},
		func() fyne.CanvasObject {
			return container.NewHBox(widget.NewLabel("Группа"), widget.NewSeparator(), widget.NewLabel("Сервис"))
		},
		func(id widget.ListItemID, o fyne.CanvasObject) {
			activeIdx := 0
			for _, e := range ctx.Entries {
				if !e.IsDeleted {
					if activeIdx == id {
						box := o.(*fyne.Container)
						gn := e.Group
						if gn == "" {
							gn = "Без группы"
						}
						box.Objects[0].(*widget.Label).SetText("[" + gn + "]")
						box.Objects[2].(*widget.Label).SetText(e.Service)
						return
					}
					activeIdx++
				}
			}
		},
	)

	ctx.List.OnSelected = func(id widget.ListItemID) {
		activeIdx := 0
		for i, e := range ctx.Entries {
			if !e.IsDeleted {
				if activeIdx == id {
					showDetailDialog(ctx, i)
					break
				}
				activeIdx++
			}
		}
		ctx.List.Unselect(id)
	}

	addBtn := widget.NewButton("Добавить запись", func() { showAddDialog(ctx) })
	trashBtn := widget.NewButton("Корзина", func() { showTrashDialog(ctx) })
	topButtons := container.NewHBox(addBtn, trashBtn)
	topButtons.Hide()

	unlockBtn := widget.NewButton("Разблокировать", func() {
		ctx.MasterPassword = passInput.Text
		data, err := storage.Load()

		if err != nil {
			dialog.ShowConfirm("База не найдена", "Файл vault.bin не существует.\nСоздать новую базу данных?", func(create bool) {
				if create {
					ctx.CurrentSalt = make([]byte, 16)
					_, _ = io.ReadFull(rand.Reader, ctx.CurrentSalt)
					ctx.Session = crypto.NewSession(ctx.MasterPassword, ctx.CurrentSalt)
					ctx.Entries = []models.Entry{}
					saveState(ctx)

					authBox.Hide()
					topButtons.Show()
					mainView.Show()
					ctx.List.Refresh()
				}
			}, w)
			return
		}

		if len(data) < 16+12 {
			dialog.ShowError(fmt.Errorf("Файл повреждён или пуст"), w)
			return
		}

		// ВАЖНО: сначала фиксируем соль из файла
		ctx.CurrentSalt = data[:16]
		
		decrypted, err := crypto.Decrypt(data, ctx.MasterPassword)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Неверный мастер-пароль"), w)
			return
		}

		// Если дешифровка успешна, сохраняем сессию
		ctx.Session = crypto.NewSession(ctx.MasterPassword, ctx.CurrentSalt)

		if err := json.Unmarshal(decrypted, &ctx.Entries); err != nil {
			dialog.ShowError(fmt.Errorf("Повреждённые данные"), w)
			return
		}

		sortEntries(ctx.Entries)
		authBox.Hide()
		topButtons.Show()
		mainView.Show()
		ctx.List.Refresh()
	})

	authBox = container.NewVBox(widget.NewLabel("Мастер-пароль:"), passInput, unlockBtn)

	// Обертка для правой кнопки
	wrappedList := NewRightClickContainer(ctx.List, func(ev *desktop.MouseEvent) {
		menu := fyne.NewMenu("Меню",
			fyne.NewMenuItem("Добавить запись", func() { showAddDialog(ctx) }),
		)
		widget.ShowPopUpMenuAtPosition(menu, w.Canvas(), ev.AbsolutePosition)
	})

	mainView = container.NewBorder(topButtons, nil, nil, nil, wrappedList)
	mainView.Hide()

	w.SetContent(container.NewStack(canvas.NewRectangle(color.Transparent), authBox, mainView))
}

func saveState(ctx *AppContext) {
	if ctx.Session == nil || ctx.CurrentSalt == nil {
		return
	}

	sortEntries(ctx.Entries)

	jsonData, err := json.Marshal(ctx.Entries)
	if err != nil {
		return
	}

	encrypted, err := ctx.Session.Encrypt(jsonData)
	if err != nil {
		return
	}

	// Всегда используем CurrentSalt, чтобы не менять ключ AES в рамках одной сессии
	final := append(ctx.CurrentSalt, encrypted...)
	err = storage.Save(final)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка сохранения: %v\n", err)
	}

	ctx.List.Refresh()
}

func showAddDialog(ctx *AppContext) {
	g := widget.NewEntry()
	g.SetPlaceHolder("Группа")
	s := widget.NewEntry()
	l := widget.NewEntry()
	p := widget.NewEntry()

	lenSlider := widget.NewSlider(8, 32)
	lenSlider.SetValue(16)

	form := container.NewVBox(
		widget.NewLabel("Группа:"), g,
		widget.NewLabel("Сервис:"), s,
		widget.NewLabel("Логин:"), l,
		widget.NewLabel("Пароль:"), p,
		widget.NewButton("Генерировать", func() {
			p.SetText(GenerateSecurePassword(int(lenSlider.Value), true))
		}),
		widget.NewLabel("Длина пароля:"), lenSlider,
	)

	dialog.ShowCustomConfirm("Новая запись", "Сохранить", "Отмена", form, func(b bool) {
		if b {
			ctx.Entries = append(ctx.Entries, models.Entry{
				Group:    g.Text,
				Service:  s.Text,
				Login:    l.Text,
				Password: p.Text,
			})
			saveState(ctx)
		}
	}, ctx.Window)
}

func showDetailDialog(ctx *AppContext, realID int) {
	entry := ctx.Entries[realID]
	passLabel := widget.NewLabel("********")

	content := container.NewVBox(
		widget.NewLabel("Сервис: "+entry.Service),
		widget.NewLabel("Логин: "+entry.Login),
		container.NewHBox(
			passLabel,
			widget.NewButton("Показать", func() {
				if passLabel.Text == "********" {
					passLabel.SetText(entry.Password)
				} else {
					passLabel.SetText("********")
				}
			}),
		),
		widget.NewButton("Копировать пароль", func() {
			fyne.CurrentApp().Clipboard().SetContent(entry.Password)
		}),
		widget.NewSeparator(),
		widget.NewButton("Удалить", func() {
			ctx.Entries[realID].IsDeleted = true
			saveState(ctx)
		}),
	)

	dialog.ShowCustom("Детали", "Закрыть", content, ctx.Window)
}

func showTrashDialog(ctx *AppContext) {
	getDeleted := func() []int {
		var ids []int
		for i, e := range ctx.Entries {
			if e.IsDeleted {
				ids = append(ids, i)
			}
		}
		return ids
	}

	deletedIDs := getDeleted()

	list := widget.NewList(
		func() int { return len(deletedIDs) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(ctx.Entries[deletedIDs[id]].Service)
		},
	)

	list.OnSelected = func(id widget.ListItemID) {
		realIdx := deletedIDs[id]
		dialog.ShowConfirm("Восстановить?", "Вернуть запись "+ctx.Entries[realIdx].Service+"?", func(b bool) {
			if b {
				ctx.Entries[realIdx].IsDeleted = false
				saveState(ctx)
				deletedIDs = getDeleted()
				list.Refresh()
			}
		}, ctx.Window)
		list.Unselect(id)
	}

	clearBtn := widget.NewButton("Очистить навсегда", func() {
		var active []models.Entry
		for _, e := range ctx.Entries {
			if !e.IsDeleted {
				active = append(active, e)
			}
		}
		ctx.Entries = active
		saveState(ctx)
		deletedIDs = getDeleted()
		list.Refresh()
	})

	content := container.NewBorder(nil, clearBtn, nil, nil, list)
	d := dialog.NewCustom("Корзина", "Закрыть", content, ctx.Window)
	d.Resize(fyne.NewSize(400, 400))
	d.Show()
}