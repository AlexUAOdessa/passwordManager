package main

import (
	"passwordManager/internal/ui"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

func main() {
    myApp := app.New()
    window := myApp.NewWindow("Password Manager")

    ui.StartUI(window)

    // Устанавливаем разумный стартовый размер
    window.Resize(fyne.NewSize(800, 600))
    window.CenterOnScreen()

    // Это "магия" для Windows: если вы хотите, чтобы окно было максимально большим 
    // при запуске, но не ломало позиционирование:
    // window.SetFixedSize(false) // по умолчанию false

    window.ShowAndRun()
}