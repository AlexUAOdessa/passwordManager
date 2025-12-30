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

// AppContext хранит состояние приложения в рамках одной сессии
type AppContext struct {
	Window         fyne.Window
	Entries        []models.Entry
	MasterPassword string
	Session        *crypto.CryptoSession
	CurrentSalt    []byte // Соль текущей открытой базы (16 байт)
	List           *widget.List
}

// RightClickContainer — виджет-обертка для обработки правой кнопки мыши
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
	return widget.NewSimpleRenderer(c.content)
}

func (c *RightClickContainer) MouseDown(ev *desktop.MouseEvent) {
	if ev.Button == desktop.MouseButtonSecondary && c.OnRightClick != nil {
		c.OnRightClick(ev)
	}
}

// Пустые методы для реализации интерфейса Mouseable
func (c *RightClickContainer) MouseUp(*desktop.MouseEvent)   {}
func (c *RightClickContainer) MouseMoved(*desktop.MouseEvent) {}
func (c *RightClickContainer) MouseIn(*desktop.MouseEvent)    {}
func (c *RightClickContainer) MouseOut()                      {}

// GenerateSecurePassword создает случайный пароль заданной длины
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

// sortEntries сортирует записи по группе и названию сервиса
func sortEntries(entries []models.Entry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Group != entries[j].Group {
			return entries[i].Group < entries[j].Group
		}
		return entries[i].Service < entries[j].Service
	})
}

// StartUI инициализирует основной интерфейс приложения
func StartUI(w fyne.Window) {
	ctx := &AppContext{Window: w}
	passInput := widget.NewPasswordEntry()
	passInput.SetPlaceHolder("Введите мастер-пароль")

	var authBox *fyne.Container
	var mainView *fyne.Container

	// Инициализация списка записей
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
			return container.NewHBox(
				widget.NewLabel("Группа"),
				widget.NewSeparator(),
				widget.NewLabel("Сервис"),
			)
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

	// Кнопка разблокировки базы
	unlockBtn := widget.NewButton("Разблокировать", func() {
		ctx.MasterPassword = passInput.Text
		data, err := storage.Load()

		if err != nil {
			dialog.ShowConfirm("База не найдена", "Файл vault.bin не найден. Создать новую базу?", func(create bool) {
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

		if len(data) < 16 {
			dialog.ShowError(fmt.Errorf("Файл базы слишком мал или поврежден"), w)
			return
		}

		// Сначала берем соль из файла
		ctx.CurrentSalt = data[:16]

		// Пытаемся расшифровать
		decrypted, err := crypto.Decrypt(data, ctx.MasterPassword)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Неверный мастер-пароль"), w)
			return
		}

		// Если успешно, создаем сессию для шифрования при будущих сохранениях
		ctx.Session = crypto.NewSession(ctx.MasterPassword, ctx.CurrentSalt)

		if err := json.Unmarshal(decrypted, &ctx.Entries); err != nil {
			dialog.ShowError(fmt.Errorf("Ошибка разбора JSON: %v", err), w)
			return
		}

		sortEntries(ctx.Entries)
		authBox.Hide()
		topButtons.Show()
		mainView.Show()
		ctx.List.Refresh()
	})

	authBox = container.NewVBox(
		widget.NewLabel("Вход в систему"),
		passInput,
		unlockBtn,
	)

	// Обертка списка для обработки клика правой кнопкой
	wrappedList := NewRightClickContainer(ctx.List, func(ev *desktop.MouseEvent) {
		menu := fyne.NewMenu("Действия",
			fyne.NewMenuItem("Добавить запись", func() {
				showAddDialog(ctx)
			}),
		)
		widget.ShowPopUpMenuAtPosition(menu, w.Canvas(), ev.AbsolutePosition)
	})

	mainView = container.NewBorder(topButtons, nil, nil, nil, wrappedList)
	mainView.Hide()

	w.SetContent(container.NewStack(
		canvas.NewRectangle(color.Transparent),
		container.NewCenter(authBox),
		mainView,
	))
}

// saveState сохраняет текущее состояние записей в файл
func saveState(ctx *AppContext) {
	if ctx.Session == nil || ctx.CurrentSalt == nil {
		return
	}

	sortEntries(ctx.Entries)

	jsonData, err := json.Marshal(ctx.Entries)
	if err != nil {
		return
	}

	// Шифруем данные (используя ту же соль и пароль из сессии)
	encrypted, err := ctx.Session.Encrypt(jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка шифрования: %v\n", err)
		return
	}

	// Склеиваем: Соль + Зашифрованные данные
	finalData := append(ctx.CurrentSalt, encrypted...)
	
	err = storage.Save(finalData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка записи: %v\n", err)
	}

	ctx.List.Refresh()
}

// showAddDialog показывает окно создания новой записи
func showAddDialog(ctx *AppContext) {
	groupEntry := widget.NewEntry()
	groupEntry.SetPlaceHolder("Напр: Работа, Игры")
	serviceEntry := widget.NewEntry()
	loginEntry := widget.NewEntry()
	passwordEntry := widget.NewEntry()

	lengthSlider := widget.NewSlider(8, 64)
	lengthSlider.SetValue(16)

	form := container.NewVBox(
		widget.NewLabel("Группа:"), groupEntry,
		widget.NewLabel("Сервис/Сайт:"), serviceEntry,
		widget.NewLabel("Логин:"), loginEntry,
		widget.NewLabel("Пароль:"), passwordEntry,
		widget.NewButton("Сгенерировать", func() {
			passwordEntry.SetText(GenerateSecurePassword(int(lengthSlider.Value), true))
		}),
		widget.NewLabel("Длина пароля:"), lengthSlider,
	)

	dialog.ShowCustomConfirm("Добавить запись", "Сохранить", "Отмена", form, func(ok bool) {
		if ok {
			newEntry := models.Entry{
				Group:    groupEntry.Text,
				Service:  serviceEntry.Text,
				Login:    loginEntry.Text,
				Password: passwordEntry.Text,
			}
			ctx.Entries = append(ctx.Entries, newEntry)
			saveState(ctx)
		}
	}, ctx.Window)
}

// showDetailDialog показывает детали записи и позволяет копировать пароль
func showDetailDialog(ctx *AppContext, realIndex int) {
	entry := ctx.Entries[realIndex]
	
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
			ctx.Window.Clipboard().SetContent(entry.Password)
		}),
		widget.NewSeparator(),
		widget.NewButton("Переместить в корзину", func() {
			ctx.Entries[realIndex].IsDeleted = true
			saveState(ctx)
		}),
	)

	dialog.ShowCustom("Детали записи", "Закрыть", content, ctx.Window)
}

// showTrashDialog показывает удаленные записи
func showTrashDialog(ctx *AppContext) {
	getDeletedIndices := func() []int {
		var list []int
		for i, e := range ctx.Entries {
			if e.IsDeleted {
				list = append(list, i)
			}
		}
		return list
	}

	indices := getDeletedIndices()

	list := widget.NewList(
		func() int { return len(indices) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(ctx.Entries[indices[id]].Service)
		},
	)

	list.OnSelected = func(id widget.ListItemID) {
		realIdx := indices[id]
		dialog.ShowConfirm("Восстановить?", "Вернуть запись "+ctx.Entries[realIdx].Service+"?", func(yes bool) {
			if yes {
				ctx.Entries[realIdx].IsDeleted = false
				saveState(ctx)
				indices = getDeletedIndices()
				list.Refresh()
			}
		}, ctx.Window)
		list.Unselect(id)
	}

	clearAllBtn := widget.NewButton("Очистить корзину навсегда", func() {
		dialog.ShowConfirm("Удаление", "Это действие нельзя отменить. Продолжить?", func(confirm bool) {
			if confirm {
				var remaining []models.Entry
				for _, e := range ctx.Entries {
					if !e.IsDeleted {
						remaining = append(remaining, e)
					}
				}
				ctx.Entries = remaining
				saveState(ctx)
				indices = getDeletedIndices()
				list.Refresh()
			}
		}, ctx.Window)
	})

	content := container.NewBorder(nil, clearAllBtn, nil, nil, list)
	d := dialog.NewCustom("Корзина (нажмите для восстановления)", "Закрыть", content, ctx.Window)
	d.Resize(fyne.NewSize(400, 400))
	d.Show()
}