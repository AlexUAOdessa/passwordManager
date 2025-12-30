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
	List           *widget.List
}

// RightClickOverlay — прозрачный слой поверх списка, ловит правую кнопку
type RightClickOverlay struct {
	widget.BaseWidget
	OnRight func(*desktop.MouseEvent)
}

func NewRightClickOverlay(onRight func(*desktop.MouseEvent)) *RightClickOverlay {
	r := &RightClickOverlay{OnRight: onRight}
	r.ExtendBaseWidget(r)
	return r
}

func (r *RightClickOverlay) CreateRenderer() fyne.WidgetRenderer {
	rect := canvas.NewRectangle(color.Transparent)
	return widget.NewSimpleRenderer(rect)
}

func (r *RightClickOverlay) MinSize() fyne.Size {
	return fyne.NewSize(0, 0) // не занимает место
}

func (r *RightClickOverlay) MouseDown(ev *desktop.MouseEvent) {
	if ev.Button == desktop.MouseButtonSecondary && r.OnRight != nil {
		r.OnRight(ev)
	}
}

func (r *RightClickOverlay) MouseUp(*desktop.MouseEvent)   {}
func (r *RightClickOverlay) MouseMoved(*desktop.MouseEvent) {}
func (r *RightClickOverlay) MouseIn(*desktop.MouseEvent)    {}
func (r *RightClickOverlay) MouseOut()                      {}

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
        // Файл не найден или другая ошибка чтения → предлагаем создать новую
        dialog.ShowConfirm("База не найдена", "Файл vault.bin не существует.\nСоздать новую базу данных?", func(create bool) {
            if create {
                salt := make([]byte, 16)
                io.ReadFull(rand.Reader, salt) // игнорируем ошибку, крайне маловероятна
                ctx.Session = crypto.NewSession(ctx.MasterPassword, salt)
                ctx.Entries = []models.Entry{}
                saveState(ctx)  // сохранит новую пустую базу
                
                authBox.Hide()
                topButtons.Show()
                mainView.Show()
                ctx.List.Refresh()
            }
        }, w)
        return
    }

    if len(data) < 16+12 {  // соль + минимум nonce
        dialog.ShowError(fmt.Errorf("Файл повреждён или пуст"), w)
        return
    }

    decrypted, err := crypto.Decrypt(data, ctx.MasterPassword)
    if err != nil {
        dialog.ShowError(fmt.Errorf("Неверный мастер-пароль"), w)
        return
    }

    salt := data[:16]
    ctx.Session = crypto.NewSession(ctx.MasterPassword, salt)

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

	// Слой для правой кнопки поверх списка
	overlay := NewRightClickOverlay(func(ev *desktop.MouseEvent) {
		menu := fyne.NewMenu("Контекст",
			fyne.NewMenuItem("Добавить запись", func() { showAddDialog(ctx) }),
		)
		widget.ShowPopUpMenuAtPosition(menu, w.Canvas(), ev.AbsolutePosition)
	})

	// Список + overlay сверху (прозрачный)
	listWithOverlay := container.NewStack(ctx.List, overlay)

	mainView = container.NewBorder(topButtons, nil, nil, nil, listWithOverlay)
	mainView.Hide()

	w.SetContent(container.NewStack(canvas.NewRectangle(color.Transparent), authBox, mainView))
}

func saveState(ctx *AppContext) {
	if ctx.Session == nil {
		return
	}

	sortEntries(ctx.Entries)

	// Всегда берём старую соль, если файл существует
	oldData, err := storage.Load()
	var salt []byte
	if err == nil && len(oldData) >= 16 {
		salt = oldData[:16]
	} else {
		salt = make([]byte, 16)
		_, _ = io.ReadFull(rand.Reader, salt)
	}

	jsonData, err := json.Marshal(ctx.Entries)
	if err != nil {
		return
	}

	encrypted, err := ctx.Session.Encrypt(jsonData)
	if err != nil {
		return
	}

	final := append(salt, encrypted...)
	err = storage.Save(final)
	if err != nil {
		// Можно вывести в консоль или диалог
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
	d := dialog.NewCustom("Корзина (нажмите для восстановления)", "Закрыть", content, ctx.Window)
	d.Resize(fyne.NewSize(400, 400))
	d.Show()
}