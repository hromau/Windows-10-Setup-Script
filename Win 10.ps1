# Remove all text from the current display
# Очистить экран
Clear-Host
# Сlear $Error variable
# Очистка переменной $Error
$Error.Clear()
# Get information about the current culture settings
# Получить сведения о параметрах текущей культуры
IF ((Get-Culture).Name -eq "ru-RU")
{
	$RU = $true
}
# Turn off diagnostics tracking services
# Отключить службы диагностического отслеживания
$services = @(
	# Connected Devices Platform service
	# Служба платформы подключенных устройств
	"CDPSvc",
	# Connected User Experiences and Telemetry
	# Функциональные возможности для подключенных пользователей и телеметрия
	"DiagTrack",
	# Data Usage
	# Использование данных
	"DusmSvc",
	# SSDP Discovery
	# Обнаружение SSDP
	"SSDPSRV"
)
Get-Service -Name $services | Stop-Service -Force
Get-Service -Name $services | Set-Service -StartupType Disabled
# Turn off the Autologger session at the next computer restart ###
# Отключить сборщик AutoLogger при следующем запуске ПК
Update-AutologgerConfig -Name AutoLogger-Diagtrack-Listener -Start 0
# Turn off the SQMLogger session at the next computer restart
# Отключить сборщик SQMLogger при следующем запуске ПК
Update-AutologgerConfig -Name SQMLogger -Start 0
# Set the operating system diagnostic data level to "Basic"
# Установить уровень отправляемых диагностических сведений на "Базовый"
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -Value 1 -Force
# Turn off Windows Error Reporting
# Отключить отчеты об ошибках Windows для всех пользователей
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Value 1 -Force
# Change Windows Feedback frequency to "Never"
# Изменить частоту формирования отзывов на "Никогда"
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Siuf\Rules))
{
	New-Item -Path HKCU:\Software\Microsoft\Siuf\Rules -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -Value 0 -Force
# Turn off diagnostics tracking scheduled tasks
# Отключить задачи диагностического отслеживания
$tasks = @(
	"ProgramDataUpdater",
	"Microsoft Compatibility Appraiser",
	"Microsoft-Windows-DiskDiagnosticDataCollector",
	"TempSignedLicenseExchange",
	"MapsToastTask",
	"DmClient",
	"FODCleanupTask",
	"DmClientOnScenarioDownload",
	"BgTaskRegistrationMaintenanceTask",
	"File History (maintenance mode)",
	"WinSAT",
	"UsbCeip",
	"Consolidator",
	"Proxy",
	"MNO Metadata Parser",
	"NetworkStateChangeTask",
	"GatherNetworkInfo",
	"XblGameSaveTask",
	"EnableLicenseAcquisition",
	"QueueReporting",
	"FamilySafetyMonitor",
	"FamilySafetyRefreshTask"
)
Get-ScheduledTask -TaskName $tasks | Disable-ScheduledTask
# Turn off "The Windows Filtering Platform has blocked a connection" message
# Отключить в "Журналах Windows/Безопасность" сообщение "Платформа фильтрации IP-пакетов Windows разрешила подключение"
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
# Set File Explorer to open to This PC by default
# Открывать "Этот компьютер" в Проводнике
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Value 1 -Force
# Show Hidden Files, Folders, and Drives
# Показывать скрытые файлы, папки и диски
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Value 1 -Force
# Show File Name Extensions
# Показывать расширения для зарегистрированных типов файлов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Value 0 -Force
# Hide Task View button on taskbar
# Не показывать кнопку Просмотра задач
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Value 0 -Force
# Show folder merge conflicts
# Не скрывать конфликт слияния папок
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -Value 0 -Force
# Turn off Snap Assist
# Не показывать при прикреплении окна, что можно прикрепить рядом с ним
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SnapAssist -Value 0 -Force
# Turn off check boxes to select items
# Отключить флажки для выбора элементов
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -Value 0 -Force
# Show seconds on taskbar clock
# Включить отображение секунд в системных часах на панели задач
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSecondsInSystemClock -Value 1 -Force
# Hide People button on the taskbar
# Не показывать панель "Люди" на панели задач
IF (-not (Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Name PeopleBand -Value 0 -Force
# Hide all folders in the navigation pane
# Не отображать все папки в области навигации
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 0 -Force
# Turn on acrylic taskbar transparency
# Включить прозрачную панель задач
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name UseOLEDTaskbarTransparency -Value 1 -Force
# Turn off app launch tracking to improve Start menu and search results
# Не разрешать Windows отслеживать запуски приложений для улучшения меню "Пуск" и результатов поиска и не показывать недавно добавленные приложения
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_TrackProgs -Value 0 -Force
# Отобразить "Этот компьютер" на рабочем столе
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Force
# Show more details in file transfer dialog
# Развернуть диалог переноса файлов
#IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
#{
#	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
#}
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -Value 1 -Force
# Turn off AutoPlay for all media and devices
# Отключить автозапуск с внешних носителей
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -Value 1 -Force
# Turn off the "- Shortcut" name extension for new shortcuts
# He дoбaвлять "- яpлык" для coздaвaeмыx яpлыкoв
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name link -PropertyType Binary -Value ([byte[]](00, 00, 00, 00)) -Force
# Turn off SmartScreen for apps and files
# Отключить SmartScreen для приложений и файлов
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force
# Remove the "Previous Versions" tab from properties context menu
# Отключить отображение вкладки "Предыдущие версии" в свойствах файлов и папок
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name NoPreviousVersionsPage -Value 1 -Force
# Always show all icons in the notification area
# Всегда отображать все значки в области уведомлений
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -Value 0 -Force
# Set the Control Panel view by large icons
# Установить крупные значки в панели управления
#IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
#{
#	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
#}
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -Value 0 -Force
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -Value 1 -Force
# Remove 3D Objects folder in "This PC" and in the navigation pane
# Скрыть папку "Объемные объекты" из "Этот компьютер" и на панели быстрого доступа
#IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"))
#{
#	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force
#}
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name ThisPCPolicy -PropertyType String -Value Hide -Force
# Make the "Open", "Print", "Edit" context menu items available, when more than 15 selected
# Сделать доступными элементы контекстного меню "Открыть", "Изменить" и "Печать" при выделении более 15 элементов
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -Value 300 -Force
# Hide "Frequent folders" in Quick access
# Не показывать недавно используемые папки на панели быстрого доступа
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Value 0 -Force
# Hide "Recent files" in Quick access
# Не показывать недавно использовавшиеся файлы на панели быстрого доступа
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Value 0 -Force
# Turn off creation of an Edge shortcut on the desktop for each user profile
# Отключить создание ярлыка Edge на рабочем столе для каждого профиля пользователя пользователя
#New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name DisableEdgeDesktopShortcutCreation -Value 1 -Force
# Turn on tip, trick, and suggestions as you use Windows
# Показывать советы, подсказки и рекомендации при использованию Windows
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -Value 1 -Force
# Turn on Storage Sense to automatically free up space
# Включить Память устройства для автоматического освобождения места
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01 -Value 1 -Force
# Run Storage Sense every month
# Запускать контроль памяти каждый месяц
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 2048 -Value 30 -Force
# Delete temporary files that apps aren't using
# Удалять временные файлы, не используемые в приложениях
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -Value 1 -Force
# Delete files in recycle bin if they have been there for over 30 days
# Удалять файлы, которые находятся в корзине более 30 дней
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 256 -Value 30 -Force
# Never delete files in "Downloads" folder
# Никогда не удалять файлы из папки "Загрузки"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 512 -Value 0 -Force
# Turn off app suggestions on Start menu
# Не показывать рекомендации в меню "Пуск"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -Value 0 -Force
# Turn off suggested content in the Settings
# Не показывать рекомендуемое содержание в приложении "Параметры"
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -Value 0 -Force
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -Value 0 -Force
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -Value 0 -Force
# Turn off automatic installing suggested apps
# Отключить автоматическую установку рекомендованных приложений
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -Value 0 -Force
# Hide "Windows Ink Workspace" button in taskbar
# Скрыть кнопку Windows Ink Workspace на панели задач
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace -Name PenWorkspaceButtonDesiredVisibility -Value 0 -Force
# Do not offer tailored experiences based on the diagnostic data setting
# Не предлагать персонализированныее возможности, основанные на выбранном параметре диагностических данных
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -Value 0 -Force
# Do not let apps on other devices open and message apps on this device, and vice versa
# Не разрешать приложениям на других устройствах запускать приложения и отправлять сообщения на этом устройстве и наоборот
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP -Name RomeSdkChannelUserAuthzPolicy -Value 0 -Force
# Choose theme color for default Windows mode
# Выбрать режим Windows по умолчанию
IF ($RU)
{
	Write-Host "`nВыберите режим Windows по умолчанию, введя букву: "
	Write-Host "[L]ight " -ForegroundColor Yellow -NoNewline
	Write-Host "для светлого режима или " -NoNewline
	Write-Host "[D]ark " -ForegroundColor Yellow -NoNewline
	Write-Host "для тёмного."
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nChoose theme color for default Windows mode by typing"
	Write-Host "[L]ight " -ForegroundColor Yellow -NoNewline
	Write-Host "for the light mode or " -NoNewline
	Write-Host "[D]ark " -ForegroundColor Yellow -NoNewline
	Write-Host "for the dark"
	Write-Host "`nPress Enter to skip" -NoNewline
}
Do
{
	$theme = Read-Host -Prompt " "
	IF ($theme -eq "L")
	{
		# Show color only on taskbar
		# Отображать цвет элементов только на панели задач
		New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name ColorPrevalence -Value 0 -Force
		# Light Theme Color for Default Windows Mode
		# Режим Windows по умолчанию светлый
		New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -Value 1 -Force
	}
	elseif ($theme -eq "D")
	{
		# Turn on the display of color on Start menu, taskbar, and action center
		# Отображать цвет элементов в меню "Пуск", на панели задач и в центре уведомлений
		New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name ColorPrevalence -Value 1 -Force
		# Dark Theme Color for Default Windows Mode
		# Режим Windows по умолчанию темный
		New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -Value 0 -Force
	}
	elseif ([string]::IsNullOrEmpty($theme))
	{
		break
	}
	else
	{
		IF ($RU)
		{
			Write-Host "`nНеправильная буква." -ForegroundColor Yellow
			Write-Host "Введите правильную букву: " -NoNewline
			Write-Host "[L]ight " -ForegroundColor Yellow -NoNewline
			Write-Host "для светлого режима или " -NoNewline
			Write-Host "[D]ark " -ForegroundColor Yellow -NoNewline
			Write-Host "для тёмного."
			Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
		}
		else
		{
			Write-Host "`nInvalid letter." -ForegroundColor Yellow
			Write-Host "Type the correct letter: " -NoNewline
			Write-Host "[L]ight " -ForegroundColor Yellow -NoNewline
			Write-Host "for the light mode or " -NoNewline
			Write-Host "[D]ark " -ForegroundColor Yellow -NoNewline
			Write-Host "for the dark."
			Write-Host "`nPress Enter to skip" -NoNewline
		}
	}
}
Until ($theme -eq "L" -or $theme -eq "D")
# Choose theme color for default app mode
# Выбрать режим приложения по умолчанию
IF ($RU)
{
	Write-Host "`nВыберите режим приложения по умолчанию, введя букву: "
	Write-Host "[L]ight " -ForegroundColor Yellow -NoNewline
	Write-Host "для светлого режима или " -NoNewline
	Write-Host "[D]ark " -ForegroundColor Yellow -NoNewline
	Write-Host "для тёмного."
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nChoose theme color for default app mode by typing"
	Write-Host "[L]ight " -ForegroundColor Yellow -NoNewline
	Write-Host "for the light mode or " -NoNewline
	Write-Host "[D]ark " -ForegroundColor Yellow -NoNewline
	Write-Host "for the dark"
	Write-Host "`nPress Enter to skip" -NoNewline
}
Do
{
	$theme = Read-Host -Prompt " "
	IF ($theme -eq "L")
	{
		# Light theme color for default app mode
		# Режим приложений по умолчанию светлый
		New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 1 -Force
	}
	IF ($theme -eq "D")
	{
		# Dark theme color for default app mode
		# Режим приложений по умолчанию темный
		New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0 -Force
	}
	elseif ([string]::IsNullOrEmpty($theme))
	{
		break
	}
	else
	{
		IF ($RU)
		{
			Write-Host "`nНеправильная буква." -ForegroundColor Yellow
			Write-Host "Введите правильную букву: " -NoNewline
			Write-Host "[L]ight " -ForegroundColor Yellow -NoNewline
			Write-Host "для светлого режима или " -NoNewline
			Write-Host "[D]ark " -ForegroundColor Yellow -NoNewline
			Write-Host "для тёмного."
			Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
		}
		else
		{
			Write-Host "`nInvalid letter." -ForegroundColor Yellow
			Write-Host "Type the correct letter: " -NoNewline
			Write-Host "[L]ight " -ForegroundColor Yellow -NoNewline
			Write-Host "for the light mode or " -NoNewline
			Write-Host "[D]ark " -ForegroundColor Yellow -NoNewline
			Write-Host "for the dark."
			Write-Host "`nPress Enter to skip" -NoNewline
		}
	}
}
Until ($theme -eq "L" -or $theme -eq "D")
# Turn off location for this device
# Отключить местоположение для этого устройства
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location -Name Value -PropertyType String -Value Deny -Force
# Turn off thumbnail cache removal
# Отключить удаление кэша миниатюр
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -Value 0 -Force
# Turn off hibernate
# Отключить гибридный спящий режим
#New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Power -Name HibernateEnabled -Value 0 -Force
# Change environment variable for $env:TEMP to $env:SystemDrive\Temp
# Изменить путь переменной среды для временных файлов на $env:SystemDrive\Temp
#IF (-not (Test-Path -Path $env:SystemDrive\Temp))
#{
#	New-Item -Path $env:SystemDrive\Temp -ItemType Directory -Force
#}
#[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "User")
#New-ItemProperty -Path HKCU:\Environment -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
#[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "User")
#New-ItemProperty -Path HKCU:\Environment -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
#[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Machine")
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
#[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Machine")
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
#[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Process")
#[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Process")
# Turn on Win32 long paths
# Включить длинные пути Win32
#New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -Value 1 -Force
# Group svchost.exe processes
# Группировать одинаковые службы в один процесс svhost.exe
$ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control -Name SvcHostSplitThresholdInKB -Value $ram -Force
# Turn on Retpoline patch against Spectre v2
# Включить патч Retpoline против Spectre v2
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Value 1024 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Value 1024 -Force
# Turn on the display of stop error information on the BSoD
# Включить дополнительную информацию при выводе BSoD
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name DisplayParameters -Value 1 -Force
# Hide search box or search icon on taskbar
# Не показывать кнопку поиска
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Value 0 -Force
# Turn on recycle bin files delete confirmation
# Запрашивать подтверждение на удалении файлов из корзины
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name ConfirmFileDelete -Value 1 -Force
# Do not preserve zone information
# Не хранить сведения о зоне происхождения вложенных файлов
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -Value 1 -Force
# Turn off Admin Approval Mode for administrators
# Отключить использование режима одобрения администратором для встроенной учетной записи администратора
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0 -Force
# Turn off user first sign-in animation
# Не показывать анимацию при первом входе в систему
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -Value 0 -Force
# Turn on access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
# Включить доступ к сетевым дискам при включенном режиме одобрения администратором при доступе из программ, запущенных с повышенными правами
#New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -Value 1 -Force
# Turn off "Look for an app in the Microsoft Store" in "Open with" dialog
# Отключить поиск программ в Microsoft Store при открытии диалога "Открыть с помощью"
#IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
#{
#	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
#}
#New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -Value 1 -Force
# Turn on ribbon in File Explorer
# Включить отображение ленты проводника в развернутом виде
#IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon))
#{
#	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Force
#}
#New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon -Name MinimizedStateTabletModeOff -Value 0 -Force
# Turn off "New App Installed" notification
# Не показывать уведомление "Установлено новое приложение"
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoNewAppAlert -Value 1 -Force
# Turn off recently added apps on Start Menu
# Не показывать недавно добавленные приложения в меню "Пуск"
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecentlyAddedApps -Value 1 -Force
# Turn off Windows Game Recording and Broadcasting
# Отключить Запись и трансляции игр Windows
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR -Name AllowgameDVR -Value 0 -Force
# Set download mode for delivery optization on "HTTP only"
# Отключить оптимизацию доставки для обновлений с других ПК
Get-Service -Name DoSvc | Stop-Service -Force
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization -Name DODownloadMode -Value 0 -Force
# Always wait for the network at computer startup and logon
# Всегда ждать сеть при запуске и входе в систему
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon"))
{
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -Value 1 -Force
# Do not allow apps to use advertising ID
# Не разрешать приложениям использовать идентификатор рекламы
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Value 0 -Force
# Turn off Cortana
# Отключить Cortana
IF (-not $RU)
{
	IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"))
	{
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Value 0 -Force
}
# Turn off Windows Defender SmartScreen for Microsoft Edge
# Отключить Windows Defender SmartScreen в Microsoft Edge
$edge = (Get-AppxPackage "Microsoft.MicrosoftEdge").PackageFamilyName
IF (-not (Test-Path -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter"))
{
	New-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Force
}
New-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name EnabledV9 -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name PreventOverride -Value 0 -Force
# Do not allow Microsoft Edge to start and load the Start and New Tab page at Windows startup and each time Microsoft Edge is closed
# Не разрешать Edge запускать и загружать страницу при загрузке Windows и каждый раз при закрытии Edge
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader -Name AllowTabPreloading -Value 0 -Force
# Do not allow Microsoft Edge to pre-launch at Windows startup, when the system is idle, and each time Microsoft Edge is closed
# Не разрешать предварительный запуск Edge при загрузке Windows, когда система простаивает, и каждый раз при закрытии Edge
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main -Name AllowPrelaunch -Value 0 -Force
# Do not allow Windows 10 to manage default printer
# Отключить управление принтером, используемым по умолчанию, со стороны Windows 10
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name LegacyDefaultPrinterMode -Value 1 -Force
# Turn off JPEG desktop wallpaper import quality reduction
# Установка качества фона рабочего стола на 100 %
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -Value 100 -Force
# Turn off sticky Shift key after pressing 5 times
# Отключить залипание клавиши Shift после 5 нажатий
New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 506 -Force
# Uninstall all UWP apps from all accounts except
# Удалить все UWP-приложения из всех учетных записей, кроме
$ExcludedApps = @(
	# iTunes
	"AppleInc.iTunes"
	# Intel UWP-panel
	# UWP-панель Intel
	"AppUp.IntelGraphicsControlPanel"
	"AppUp.IntelGraphicsExperience"
	# Microsoft Desktop App Installer
	"Microsoft.DesktopAppInstaller"
	# Extensions
	# Расширения
	"Microsoft.*Extension*"
	# Language pack
	# Языковой пакет
	"Microsoft.LanguageExperiencePack*"
	# Screen Sketch
	# Набросок на фрагменте экрана
	"Microsoft.ScreenSketch"
	# Photos
	# Фотографии
	"Microsoft.Windows.Photos"
	# Start
	# Меню "Пуск"
	"Microsoft.Windows.StartMenuExperienceHost"
	# NVIDIA Control Panel
	# Панель управления NVidia
	"NVIDIACorp.NVIDIAControlPanel"
	# Microsoft Store
	".*Store.*"
)
$OFS = "|"
Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Where-Object {$_.Name -cnotmatch $ExcludedApps} | Remove-AppxPackage -AllUsers
$OFS = " "
# Uninstall all UWP apps from all accounts except
# Удалить все UWP-приложения из системной учетной записи, кроме
$ExcludedApps = @(
	# Intel UWP-panel
	# UWP-панель Intel
	"AppUp.IntelGraphicsControlPanel"
	"AppUp.IntelGraphicsExperience"
	# Microsoft Desktop App Installer
	"Microsoft.DesktopAppInstaller"
	# Extensions
	# Расширения
	"Microsoft.*Extension*"
	# NVIDIA Control Panel
	# Панель управления NVidia
	"NVIDIACorp.NVIDIAControlPanel"
	# Microsoft Store
	".*Store.*"
)
$OFS = "|"
Get-AppxProvisionedPackage -Online | Where-Object -FilterScript {$_.DisplayName -cnotmatch $ExcludedApps} | Remove-AppxProvisionedPackage -Online
$OFS = " "
# Turn off Windows features
# Отключить компоненты
$features = @(
	# Windows Fax and Scan
	# Факсы и сканирование
	"FaxServicesClientPackage",
	# Legacy Components
	# Компоненты прежних версий
	"LegacyComponents",
	# Media Features
	# Компоненты работы с мультимедиа
	"MediaPlayback",
	# PowerShell 2.0
	"MicrosoftWindowsPowerShellV2",
	"MicrosoftWindowsPowershellV2Root",
	# Microsoft XPS Document Writer
	# Средство записи XPS-документов (Microsoft)
	"Printing-XPSServices-Features",
	# Microsoft Print to PDF
	# Печать в PDF (Майкрософт)
#	"Printing-PrintToPDFServices-Features",
	# Work Folders Client
	# Клиент рабочих папок
	"WorkFolders-Client"
)
foreach ($feature in $features)
{
	Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
}
# Uninstall Onedrive
# Удалить OneDrive
Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
Start-Process -FilePath "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
Stop-Process -Name explorer
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSync -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableMeteredNetworkFileSync -Value 0 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableLibrariesDefaultSaveToOneDrive -Value 1 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\OneDrive -Name DisablePersonalSync -Value 1 -Force
Remove-ItemProperty -Path HKCU:\Environment -Name OneDrive -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:USERPROFILE\OneDrive -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:LOCALAPPDATA\Microsoft\OneDrive -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false
# Turn on updates for other Microsoft products
# Включить автоматическое обновление для других продуктов Microsoft
(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "")
# Turn off Game Bar
# Отключить игровую панель
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR -Name AppCaptureEnabled -Value 0 -Force
New-ItemProperty -Path HKCU:\System\GameConfigStore -Name GameDVR_Enabled -Value 0 -Force
# Turn off Game Mode
# Отключить игровой режим
#New-ItemProperty -Path HKCU:\Software\Microsoft\GameBar -Name AllowAutoGameMode -Value 0 -Force
# Turn off Game Bar tips
# Отключить подсказки игровой панели
New-ItemProperty -Path HKCU:\Software\Microsoft\GameBar -Name ShowStartupPanel -Value 0 -Force
# Enable System Restore
# Включить восстановление системы
#Enable-ComputerRestore -Drive $env:SystemDrive
#Get-ScheduledTask -TaskName SR | Enable-ScheduledTask
#Get-Service -Name swprv, vss | Set-Service -StartupType Manual
#Get-Service -Name swprv, vss | Start-Service
#Get-CimInstance -ClassName Win32_ShadowCopy | Remove-CimInstance
# Turn off Windows Script Host
# Отключить Windows Script Host
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -Value 0 -Force
# Create scheduled task with the disk cleanup tool in Task Scheduler. The task runs every 90 days
# Создать в Планировщике задач задачу по запуску очистки диска. Задача выполняется каждые 90 дней
$keys = @(
	# Delivery Optimization Files
	# Файлы оптимизации доставки
	"Delivery Optimization Files",
	# Device driver packages
	# Пакеты драйверов устройств
	"Device Driver Packages",
	# Previous Windows Installation(s)
	# Предыдущие установки Windows
	"Previous Installations",
	# Файлы журнала установки
	"Setup Log Files",
	# Temporary Setup Files
	"Temporary Setup Files",
	# Windows Update Cleanup
	# Очистка обновлений Windows
	"Update Cleanup",
	# Windows Defender Antivirus
	"Windows Defender",
	# Windows upgrade log files
	# Файлы журнала обновления Windows
	"Windows Upgrade Log Files")
foreach ($key in $keys)
{
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$key" -Name StateFlags1337 -Value 2 -Force
}
$action = New-ScheduledTaskAction -Execute "cleanmgr.exe" -Argument "/sagerun:1337"
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 90 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
$params = @{
	"TaskName"	=	"Update Cleanup"
	"Action"	=	$action
	"Trigger"	=	$trigger
	"Settings"	=	$settings
	"Principal"	=	$principal
}
Register-ScheduledTask @params -Force
# Create task to clean out the "$env:SystemRoot\SoftwareDistribution\Download" folder in Task Scheduler.. The task runs on Thursdays every 4 weeks.
# Создать в Планировщике задач задачу по очистке папки "$env:SystemRoot\SoftwareDistribution\Download". Задача выполняется по четвергам каждую 4 неделю.
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	`$getservice = Get-Service -Name wuauserv
	`$getservice.WaitForStatus("Stopped", "01:00:00")
	Get-ChildItem -Path `$env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
"@
$trigger = New-JobTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Thursday -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId System -RunLevel Highest
$params = @{
	"TaskName"	=	"SoftwareDistribution"
	"Action"	=	$action
	"Trigger"	=	$trigger
	"Settings"	=	$settings
	"Principal"	=	$principal
}
Register-ScheduledTask @params -Force
# Create scheduled task with the $env:TEMP folder cleanup in Task Scheduler. The task runs every 62 days
# Создать в Планировщике задач очистки папки $env:TEMP. Задача выполняется каждые 62 дня
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	Get-ChildItem -Path `$env:TEMP -Force -Recurse | Remove-Item -Force -Recurse
"@
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 62 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId System -RunLevel Highest
$params = @{
	"TaskName"	=	"Temp"
	"Action"	=	$action
	"Trigger"	=	$trigger
	"Settings"	=	$settings
	"Principal"	=	$principal
}
Register-ScheduledTask @params -Force
# Turn off default background apps except
# Запретить стандартным приложениям работать в фоновом режиме, кроме
$apps = @(
	# Content Delivery Manager
	"Microsoft.Windows.ContentDeliveryManager*"
	# Cortana
	#"Microsoft.Windows.Cortana*"
	# Windows Security
	# Безопасность Windows
	#"Microsoft.Windows.SecHealthUI*"
	# ShellExperienceHost
	#"Microsoft.Windows.ShellExperienceHost*"
	# StartMenuExperienceHost
	"Microsoft.Windows.StartMenuExperienceHost*")
foreach ($app in $apps)
{
	Get-ChildItem -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications -Exclude $apps |
	ForEach-Object -Process {
		New-ItemProperty -Path $_.PsPath -Name Disabled -Value 1 -Force
		New-ItemProperty -Path $_.PsPath -Name DisabledByUser -Value 1 -Force
	}
}
# Set power management scheme for desktop and laptop
# Установить схему управления питания для стационарного ПК и ноутбука
IF ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 1)
{
	# High performance for desktop
	# Высокая производительность для стационарного ПК
	powercfg /setactive SCHEME_MIN
}
IF ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -eq 2)
{
	# Balanced for laptop
	# Сбалансированная для ноутбука
	powercfg /setactive SCHEME_MIN
}
# Turn on .NET 4 runtime for all apps
# Использовать последнюю установленную версию .NET Framework для всех приложений
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework -Name OnlyUseLatestCLR -Value 1 -Force
# Turn on Num Lock at startup
# Включить Num Lock при загрузке
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType String -Value 2147483650 -Force
# Add folder to exclude from Windows Defender Antivirus scan
# Добавить папку в список исключений сканирования Защитника Windows
IF ($RU)
{
	Write-Host "`nВведите полные пути до файлов или папок, которые следует "
	Write-Host "исключить из списка сканирования Windows Defender."
	Write-Host "Пути должны быть разделены запятыми и взяты в кавычки." -ForegroundColor Yellow
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nType the full paths to files or folders, which to exclude "
	Write-Host "from Windows Defender Antivirus Scan."
	Write-Host "The paths must be separated by commas and taken in quotes." -ForegroundColor Yellow
	Write-Host "`nPress Enter to skip" -NoNewline
}
function ExclusionPath
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $True)]
		[string[]]$paths
	)
	$paths = $paths.Replace("`"", "").Split(",").Trim()
	Add-MpPreference -ExclusionPath $paths -Force
}
Do
{
	$paths = Read-Host -Prompt " "
	IF ($paths -match "`"")
	{
		ExclusionPath $paths
	}
	elseif ([string]::IsNullOrEmpty($paths))
	{
		break
	}
	else
	{
		IF ($RU)
		{
			Write-Host "`nПути не взяты в кавычки." -ForegroundColor Yellow
			Write-Host "Введите пути, взяв в кавычки и разделив запятыми."
			Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
		}
		else
		{
			Write-Host "`nThe paths hasn't been taken in quotes." -ForegroundColor Yellow
			Write-Host "Type the paths by quoting and separating by commas."
			Write-Host "`nPress Enter to skip" -NoNewline
		}
	}
}
Until ($paths -match "`"")
function Get-ResolvedPath
{
	param (
		[Parameter(ValueFromPipeline = 1)]
		$Path
	)
	(Get-Disk | Where-Object -FilterScript {$_.IsBoot -eq $false} | Get-Partition | Get-Volume | Where-Object -FilterScript {$null -ne $_.DriveLetter}).DriveLetter | ForEach-Object -Process {Join-Path ($_ + ":") $Path -Resolve -ErrorAction SilentlyContinue}
}
$folder = "Программы\Прочее" | Get-ResolvedPath
IF ($folder)
{
	Add-MpPreference -ExclusionPath $folder -Force
}
# Turn on Windows Defender Exploit Guard Network Protection
# Включить Защиту сети в Защитнике Windows
#Set-MpPreference -EnableNetworkProtection Enabled
# Turn on Controlled folder access and add protected folders
# Включить контролируемый доступ к папкам и добавить защищенные папки
IF ($RU)
{
	Write-Host "`nВведите путь до папки, чтобы добавить в список защищенных папок."
	Write-Host "Пути должны быть разделены запятыми и взяты в кавычки." -ForegroundColor Yellow
	Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
}
else
{
	Write-Host "`nType folder path to add to protected folders list."
	Write-Host "The paths must be separated by commas and taken in quotes." -ForegroundColor Yellow
	Write-Host "`nPress Enter to skip" -NoNewline
}
function ControlledFolder
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $True)]
		[string[]]$paths
	)
	Set-MpPreference -EnableControlledFolderAccess Enabled
	$paths = $paths.Replace("`"", "").Split(",").Trim()
	Add-MpPreference -ControlledFolderAccessProtectedFolders $paths
}
Do
{
	$paths = Read-Host -Prompt " "
	IF ($paths -match "`"")
	{
		ControlledFolder $paths
	}
	elseif ([string]::IsNullOrEmpty($paths))
	{
		break
	}
	else
	{
		IF ($RU)
		{
			Write-Host "`nПути не взяты в кавычки." -ForegroundColor Yellow
			Write-Host "Введите пути, взяв в кавычки и разделив запятыми."
			Write-Host "`nЧтобы пропустить, нажмите Enter" -NoNewline
		}
		else
		{
			Write-Host "`nThe paths hasn't been taken in quotes." -ForegroundColor Yellow
			Write-Host "Type the paths by quoting and separating by commas."
			Write-Host "`nPress Enter to skip" -NoNewline
		}
	}
}
Until ($paths -match "`"")
# Turn on Windows Defender PUA Protection
# Включить блокировки потенциально нежелательных приложений
#Set-MpPreference -PUAProtection Enabled
# Turn on firewall & network protection
# Включить брандмауэр
Set-NetFirewallProfile -Enabled True
# Turn off F1 Help key
# Отключить справку по нажатию F1
IF (-not (Test-Path -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"))
{
	New-Item -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force
}
New-ItemProperty -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(default)" -PropertyType String -Value "" -Force
# Show Task Manager details
# Раскрыть окно Диспетчера задач
$taskmgr = Get-Process -Name Taskmgr -ErrorAction SilentlyContinue
IF ($taskmgr)
{
	$taskmgr.CloseMainWindow()
}
$taskmgr = Start-Process -FilePath taskmgr.exe -WindowStyle Hidden -PassThru
Do
{
	Start-Sleep -Milliseconds 100
	$preferences = Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -ErrorAction SilentlyContinue
}
Until ($preferences)
Stop-Process -Name $taskmgr
$preferences.Preferences[28] = 0
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -PropertyType Binary -Value $preferences.Preferences -Force
# Do not allow the computer to turn off the device to save power for desktop


# Удалить пункт "Восстановить прежнюю версию" из контекстного меню
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{596AB062-B4D2-4215-9F74-E9109B0A8153}" -PropertyType String -Value "" -Force
# Remove "Edit with Paint 3D" from context menu
# Удалить пункт "Изменить с помощью Paint 3D" из контекстного меню
$exts = @(".bmp", ".gif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
foreach ($ext in $exts)
{
	New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\$ext\Shell\3D Edit" -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}
# Remove "Include in Library" from context menu
# Удалить пункт "Добавить в библиотеку" из контекстного меню
New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location" -Name "(default)" -PropertyType String -Value "-{3dad6c5d-2167-4cae-9914-f99e41c12cfa}" -Force
# Remove "Turn on BitLocker" from context menu
# Удалить пункт "Включить Bitlocker" из контекстного меню
IF (Get-WindowsEdition -Online | Where-Object -FilterScript {$_.Edition -eq "Professional" -or $_.Edition -eq "Enterprise"})
{
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\manage-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde-elev -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\unlock-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}
# Remove "Edit with Photos" from context menu
# Удалить пункт "Изменить с помощью приложения "Фотографии"" из контекстного меню
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
# Remove "Create a new video" from Context Menu
# Удалить пункт "Создать новое видео" из контекстного меню
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
# Remove "Edit" from Context Menu
# Удалить пункт "Изменить" из контекстного меню
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\edit -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
# Remove "Print" from batch and cmd files context menu
# Удалить пункт "Печать" из контекстного меню для bat- и cmd-файлов
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\batfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force

# Turn off per-user services
# Отключить пользовательские службы
$services = @(
	# Contact Data
	# Служба контактных данных
	"PimIndexMaintenanceSvc_*",
	# User Data Storage
	# Служба хранения данных пользователя
	"UnistoreSvc_*",
	# User Data Access
	# Служба доступа к данным пользователя
	"UserDataSvc_*"
)
Get-Service -Name $services | Stop-Service -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\PimIndexMaintenanceSvc -Name Start -Value 4 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\PimIndexMaintenanceSvc -Name UserServiceFlags -Value 0 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UnistoreSvc -Name Start -Value 4 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UnistoreSvc -Name UserServiceFlags -Value 0 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UserDataSvc -Name Start -Value 4 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UserDataSvc -Name UserServiceFlags -Value 0 -Force
# Let Windows try to fix apps so they're not blurry
# Разрешить Windows исправлять размытость в приложениях
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name EnablePerProcessSystemDPI -Value 1 -Force
# Hide notification about sign in with Microsoft in the Windows Security
# Скрыть уведомление Защитника Windows об использовании аккаунта Microsoft
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name AccountProtection_MicrosoftAccount_Disconnected -Value 1 -Force
# Hide notification about disabled Smartscreen for Microsoft Edge
# Скрыть уведомление Защитника Windows об отключенном фильтре SmartScreen для Microsoft Edge
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name AppAndBrowser_EdgeSmartScreenOff -Value 0 -Force
# Remove Windows capabilities
# Удалить компоненты
$IncludedApps = @(
	# Microsoft Quick Assist
	# Быстрая поддержка (Майкрософт)
	"App.Support.QuickAssist*"
	# Windows Hello Face
	# Распознавание лиц Windows Hello
	"Hello.Face*"
	# Windows Media Player
	# Проигрыватель Windows Media
	"Media.WindowsMediaPlayer*"
)
$OFS = "|"
Get-WindowsCapability -Online | Where-Object -FilterScript {$_.Name -cmatch $IncludedApps} | Remove-WindowsCapability -Online
$OFS = " "
# Open shortcut to the Command Prompt from Start menu as Administrator
# Запускать ярлык к командной строке в меню "Пуск" от имени Администратора
$bytes = [System.IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk")
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk", $bytes)
# Automatically adjust active hours for me based on daily usage
# Автоматически изменять период активности для этого устройства на основе действий
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name SmartActiveHoursState -Value 1 -Force
# Turn on automatic recommended troubleshooting
# Устранять проблемы без запроса
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation))
{
	New-Item -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Name UserPreference -Value 4 -Force
# Turn off reserved storage
# Отключить зарезервированное хранилище
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager -Name BaseHardReserveSize -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager -Name BaseSoftReserveSize -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager -Name HardReserveAdjustment -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager -Name MinDiskSize -PropertyType QWord -Value 0 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager -Name ShippedWithReserves -Value 0 -Force
# Turn on automatic backup the system registry to the "$env:SystemRoot\System32\config\RegBack" folder
# Включить автоматическое создание копии реестра в папку "$env:SystemRoot\System32\config\RegBack"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name EnablePeriodicBackup -Value 1 -Force
# Restart Start menu
# Перезапустить меню "Пуск"
Stop-Process -Name StartMenuExperienceHost -Force
# Refresh desktop icons, environment variables and taskbar without restarting File Explorer
# Обновить иконки рабочего стола, переменные среды и панель задач без перезапуска "Проводника"
$UpdateEnvExplorerAPI = @{
	Namespace = "WinAPI"
	Name = "UpdateEnvExplorer"
	Language = "CSharp"
	MemberDefinition = @"
		private static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);
		private const int WM_SETTINGCHANGE = 0x1a;
		private const int SMTO_ABORTIFHUNG = 0x0002;
		[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		static extern bool SendNotifyMessage(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);
		[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		private static extern IntPtr SendMessageTimeout(IntPtr hWnd, int Msg, IntPtr wParam, string lParam, int fuFlags, int uTimeout, IntPtr lpdwResult);
		[DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)]
		private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
		public static void Refresh()
		{
			// Update desktop icons
			SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
			// Update environment variables
			SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, null, SMTO_ABORTIFHUNG, 100, IntPtr.Zero);
			// Update taskbar
			SendNotifyMessage(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "TraySettings");
		}
"@
}
IF (-not ("WinAPI.UpdateEnvExplorer" -as [type]))
{
	Add-Type @UpdateEnvExplorerAPI
}
[WinAPI.UpdateEnvExplorer]::Refresh()
# Errors output
# Вывод ошибок
Write-Host "`nErrors" -BackgroundColor Red
($Error | Where-Object -FilterScript {$_ -notmatch "Taskmgr" -and $_ -notmatch "TaskManager"} | ForEach-Object -Process {
	[PSCustomObject] @{
		Line = $_.InvocationInfo.ScriptLineNumber
		Error = $_.Exception.Message
	}
} | Format-Table -AutoSize -Wrap | Out-String).Trim()
