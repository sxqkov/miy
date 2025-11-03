from pystyle import Colorate, Colors
import time
import hashlib
import os
import subprocess
import shutil
import sys

GREEN = '\x1b[32m'
RESET = '\x1b[39m'
RED = '\x1b[31m'

"""def check_hwid():
    try:
        hwid_raw = subprocess.check_output('wmic csproduct get uuid', shell=True).decode().split('\n')[1].strip()
        hwid_hash = hashlib.sha256(hwid_raw.encode()).hexdigest()
        print('Проверка...')
        time.sleep(0.4)
        print('Доступ разрешён.')
        time.sleep(1)
    except Exception as e:
        print('Ошибка проверки HWID: ' + str(e))
        time.sleep(5)
        os._exit(0)""" 
#this was patched in 443 line just commented 4fun (guard in 1 line so ass)

def exit():
    sys.exit()

def musor():
    os.system('cls')
    print(RESET + '\n\n')
    print('Удаление ненужных файлов...')
    print(GREEN + '\n\n')
    reg_commands = [
        'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit" /va /f',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit" /va /f',
        'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit\\Favorites" /va /f',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit\\Favorites" /va /f',
        'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU" /va /f',
        'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRULegacy" /va /f',
        'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Paint\\Recent File List" /va /f',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Applets\\Paint\\Recent File List" /va /f',
        'reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Applets\\Wordpad\\Recent File List" /va /f',
        'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU" /va /f',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU" /va /f',
        'reg delete "HKCU\\Software\\Microsoft\\Search Assistant\\ACMru" /va /f',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" /va /f',
        'reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" /va /f',
        'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU" /va /f',
        'reg delete "HKCU\\Software\\Microsoft\\MediaPlayer\\Player\\RecentFileList" /va /f',
        'reg delete "HKCU\\Software\\Microsoft\\MediaPlayer\\Player\\RecentURLList" /va /f',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\MediaPlayer\\Player\\RecentFileList" /va /f',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\MediaPlayer\\Player\\RecentURLList" /va /f',
        'reg delete "HKCU\\SOFTWARE\\Microsoft\\Direct3D\\MostRecentApplication" /va /f',
        'reg delete "HKLM\\SOFTWARE\\Microsoft\\Direct3D\\MostRecentApplication" /va /f',
        'reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" /va /f',
        'reg delete "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths" /va /f'
    ]
    for command in reg_commands:
        subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    file_commands = [
        'c:\\windows\\temp\\*.*',
        '%userprofile%\\Recent\\*.*',
        'c:\\Windows\\Prefetch\\*.*',
        '%userprofile%\\AppData\\Local\\Temp\\*.*',
        '%userprofile%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*.*',
        '%TEMP%\\*',
        'C:\\$Recycle.Bin\\*',
        'C:\\Windows\\SoftwareDistribution\\Download\\*',
        'C:\\Windows\\SoftwareDistribution\\DataStore\\*'
    ]
    for command in file_commands:
        command_expanded = os.path.expandvars(command)
        folder = command_expanded.split('\\*')[0]
        print('Удаление в: ' + folder)
        result = subprocess.run('del /s /f /q ' + command_expanded, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print('Удалено')
        if not os.path.exists(folder):
            continue
        print('Путь: ' + folder)
        subprocess.run('rd /s /q ' + folder, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print('Удалено')
    print('\n\n')
    print(RESET + 'Успешно')
    print('\n\n')
    time.sleep(2)
    main()

def reset_internet():
    os.system('cls')
    print(RESET + 'Сброс сетевых параметров...')
    print(GREEN + '\n\n')
    netsh_commands = [
        'netsh int ip reset global',
        'netsh winsock reset',
        'netsh int tcp reset',
        'netsh int ip reset',
        'netsh nap reset',
        'netsh rpc reset',
        'netsh winhttp reset',
        'netsh http flush',
        'netsh routing reset',
        'netsh int ipv4 reset',
        'netsh int ipv6 reset',
        'netsh int ip reset all',
        'netsh winsock reset',
        'netsh advfirewall reset',
        'nbtstat -R',
        'nbtstat -RR'
    ]
    for command in netsh_commands:
        subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print('Команда выполнена')
    print('\n\n')
    print(RESET + 'Параметры TCP/IP успешно сброшены')
    print('\n\n')
    time.sleep(2)
    main()

def optimize_internet():
    os.system('cls')
    print('\n\n')
    print(RESET + 'Оптимизация сетевых параметров...')
    print(GREEN + '\n\n')
    netsh_commands = [
        'netsh int tcp set global rsc=enabled',
        'netsh int tcp set global ecncapability=disabled',
        'netsh int tcp set global autotuninglevel=disabled',
        'netsh int tcp set heuristics disabled',
        'netsh int tcp set global chimney=disabled',
        'netsh int tcp set global dca=enabled',
        'netsh int tcp set global rss=enabled',
        'netsh int tcp set global netdma=enabled',
        'netsh int tcp set global congestionprovider=ctcp',
        'netsh int tcp set global timestamps=disabled',
        'netsh int tcp set global nonsackrttresiliency=disabled',
        'netsh int tcp set supplemental template=custom icw=10'
    ]
    for command in netsh_commands:
        subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print('Команда выполнена')
    print('\n\n')
    print(RESET + 'Успешно')
    print('\n\n')
    time.sleep(2)
    main()

def disable_services():
    os.system('cls')
    print('\n\n')
    print('Отключение и настройка служб...')
    print('\n\n')
    service_commands = [
        ('Fax', 'Fax'),
        ('NetTcpPortSharing', 'NetTcpPortSharing'),
        ('workfolderssvc', 'workfolderssvc'),
        ('AJRouter', 'AJRouter'),
        ('AppIDSvc', 'AppIDSvc'),
        ('BDESVC', 'BDESVC'),
        ('irmon', 'irmon'),
        ('vmicvmsession', 'vmicvmsession'),
        ('vmicrdv', 'vmicrdv'),
        ('lfsvc', 'lfsvc'),
        ('vmicshutdown', 'vmicshutdown'),
        ('vmicvss', 'vmicvss'),
        ('vmickvpexchange', 'vmickvpexchange'),
        ('vmicheartbeat', 'vmicheartbeat'),
        ('vmictimesync', 'vmictimesync'),
        ('HvHost', 'HvHost'),
        ('vmicguestinterface', 'vmicguestinterface'),
        ('SensorDataService', 'SensorDataService'),
        ('SensorService', 'SensorService'),
        ('SensrSvc', 'SensrSvc'),
        ('SEMgrSvc', 'SEMgrSvc'),
        ('RemoteAccess', 'RemoteAccess'),
        ('SessionEnv', 'SessionEnv'),
        ('SharedAccess', 'SharedAccess'),
        ('SCPolicySvc', 'SCPolicySvc'),
        ('CertPropSvc', 'CertPropSvc'),
        ('TermService', 'TermService'),
        ('TrkWks', 'TrkWks'),
        ('WpcMonSvc', 'WpcMonSvc'),
        ('FrameServer', 'FrameServer'),
        ('ScDeviceEnum', 'ScDeviceEnum'),
        ('WinRM', 'WinRM'),
        ('SCardSvr', 'SCardSvr'),
        ('PhoneSvc', 'PhoneSvc'),
        ('RemoteRegistry', 'RemoteRegistry'),
        ('DiagTrack', 'DiagTrack'),
        ('dmwappushservice', 'dmwappushservice'),
        ('DcpSvc', 'DcpSvc'),
        ('WerSvc', 'WerSvc'),
        ('PcaSvc', 'PcaSvc'),
        ('DoSvc', 'DoSvc'),
        ('WMPNetworkSvc', 'WMPNetworkSvc')
    ]
    for service, display_name in service_commands:
        subprocess.run('sc stop ' + service, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run('sc config "' + service + '" start= disabled', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(GREEN + 'Служба ' + display_name + ' отключена и настроена на отключение.')
    print('\n\n')
    print(RESET + 'Успешно')
    print('\n\n')
    time.sleep(2)
    main()

def smartscreen():
    os.system('cls')
    print('\n\n')
    print('Отключение SmartScreen...')
    print(GREEN + '\n\n')
    reg_commands2 = [
        'Reg.exe add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "off" /f',
        'Reg.exe add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0x0" /f',
        'Reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0x0" /f',
        'Reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v "EnableSmartScreen" /t REG_DWORD /d "0x0" /f'
    ]
    for command in reg_commands2:
        process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode == 0:
            print('Команда выполнена: ' + command)
        else:
            print('Ошибка при выполнении команды: ' + command)
    print('\n\n')
    print(RESET + 'Успешно')
    print('\n\n')
    time.sleep(2)
    main()

def telemetry():
    os.system('cls')
    print('\n\n')
    print('Отключение телеметрии')
    print(GREEN + '\n\n')
    telemetry_commands = [
        'netsh advfirewall firewall add rule name="telemetry_watson.telemetry.microsoft.com" dir=out action=block remoteip=65.55.252.43,65.52.108.29 enable=yes',
        'PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList \'-NoProfile -ExecutionPolicy Bypass -File ""%~dp0.\\ms_new.ps1""\' -Verb RunAs}"',
        'reg add "HKLM\\SYSTEM\\ControlSet001\\Control\\WMI\\AutoLogger\\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\diagnosticshun.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f',
        'reg add "HKCU\\SOFTWARE\\Microsoft\\Personalization\\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\SOFTWARE\\Microsoft\\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\SOFTWARE\\Microsoft\\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\SOFTWARE\\Microsoft\\InputPersonalization\\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\TabledPC" /v "PreventHandwritingdataSharing" /t REG_DWORD /d 1 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f',
        'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\SOFTWARE\\Microsoft\\MediaPlayer\\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\SOFTWARE\\Microsoft\\Siuf\\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\SOFTWARE\\Microsoft\\Siuf\\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\Assistance\\Client\\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f',
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Input\\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\SOFTWARE\\Microsoft\\Input\\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f'
    ]
    for command in telemetry_commands:
        process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode == 0:
            print('Команда выполнена: ' + command)
        else:
            print('Ошибка при выполнении команды: ' + command)
    print('\n\n')
    print(RESET + 'Успешно')
    print('\n\n')
    time.sleep(2)
    main()

def bcdedit_tweaks():
    os.system('cls')
    print('\n\n')
    print('Повышение производительности...')
    print(GREEN + '\n\n')
    bcdedit_commands = [
        'bcdedit -set disabledynamictick yes',
        'bcdedit -set useplatformtick yes'
    ]
    for command in bcdedit_commands:
        try:
            print('Выполняется ' + command)
            subprocess.run(command, shell=True, check=True)
            print('Команда ' + command + ' выполнена успешно.')
        except subprocess.CalledProcessError as e:
            print('Ошибка при выполнении команды ' + command + ': ' + str(e))
    print('\n\n')
    print(RESET + 'Успешно')
    print('\n\n')
    time.sleep(2)
    main()

def optimize_internet2():
    os.system('cls')
    print('\n\n')
    print('Оптимизация сетевых параметров...')
    print(GREEN + '\n\n')
    netsh_commands2 = [
        'netsh int tcp set global autotuninglevel=normal',
        'netsh interface 6to4 set state disabled',
        'netsh int isatap set state disable',
        'netsh int tcp set global timestamps=disabled',
        'netsh int tcp set heuristics disabled',
        'int tcp set global chimney=disabled',
        'netsh int tcp set global ecncapability=disabled',
        'netsh int tcp set global rsc=disabled',
        'netsh int tcp set global nonsackrttresiliency=disabled',
        'netsh int tcp set security mpp=disabled',
        'netsh int tcp set security profiles=disabled',
        'netsh int ip set global icmpredirects=disabled',
        'netsh int tcp set security mpp=disabled profiles=disabled',
        'netsh int ip set global multicastforwarding=disabled',
        'netsh int tcp set supplemental internet congestionprovider=ctcp',
        'netsh interface teredo set state disabled',
        'netsh winsock reset',
        'netsh int isatap set state disable',
        'netsh int ip set global taskoffload=disabled',
        'netsh int ip set global neighborcachelimit=4096',
        'netsh int tcp set global dca=enabled',
        'netsh int tcp set global netdma=enabled'
    ]
    for command in netsh_commands2:
        subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print('Команда выполнена')
    print('\n\n')
    print(RESET + 'Успешно')
    print('\n\n')
    time.sleep(2)
    main()

def clear_event_logs():
    os.system('cls')
    try:
        logs = subprocess.check_output('wevtutil enum-logs', shell=True, text=True)
        logs = logs.splitlines()
        for log in logs:
            log = log.strip()
            if not log:
                continue
            print(GREEN + 'Удаление: ' + log)
            subprocess.run('wevtutil clear-log ' + log, shell=True)
        print('\n\n')
        print(RESET + 'Все журналы событий очищены.')
    except Exception as e:
        print('Ошибка при очистке журналов событий: ' + str(e))
    print('\n\n')
    print(RESET + 'Успешно')
    print('\n\n')
    time.sleep(2)
    main()

def delete_old_windows():
    os.system('cls')
    windows_old_path = 'C:\\Windows.old'
    if os.path.exists(windows_old_path):
        try:
            shutil.rmtree(windows_old_path)
            print('\n\n')
            print('Папка ' + windows_old_path + ' успешно удалена.')
        except Exception as e:
            print('Ошибка при удалении папки: ' + str(e))
    else:
        print('\n\n')
        print('Папка ' + windows_old_path + ' не найдена.')
    print('\n\n')
    time.sleep(2)
    main()

def menu():
    console_width = os.get_terminal_size().columns
    menu = [
        '[1] Удаление мусорных файлов',
        '[2] Оптимизация параметров TCP/IP',
        '[3] Восстановление параметров TCP/IP',
        '[4] Отключение ненужных служб',
        '[5] Отключение SmartScreen',
        '[6] Отключение телеметрии',
        '[7] Отключение НРЕТ',
        '[8] Альтернативная настройка TCP/IP',
        '[9] Очистка логов Windows',
        '[10] Удаление файлов старой Windows',
        '[0] Exit'
    ]
    for item in menu:
        miy_art = item.center(console_width - 2)
        print(Colorate.Horizontal(Colors.cyan_to_green, miy_art))

def main():
    os.system('cls')
    art = [
        '███╗   ███╗██╗██╗   ██╗',
        '████╗ ████║██║╚██╗ ██╔╝',
        '██╔████╔██║██║ ╚████╔╝ ',
        '██║╚██╔╝██║██║   ██╔╝  ',
        '██║ ╚═╝ ██║██║   ██║   ',
        '╚═╝     ╚═╝╚═╝   ╚═╝   '
    ]
    console_width = os.get_terminal_size().columns
    print('\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n')
    for line in art:
        centered_line = line.center(console_width - 2)
        print(Colorate.Horizontal(Colors.cyan_to_green, centered_line))
    print('\n')
    menu()
    print('\n\n\n\n\n\n')
    vibor_gradient = '[?] Выберите команду: '
    vibor_gradient = Colorate.Horizontal(Colors.green_to_red, vibor_gradient)
    choice = input(vibor_gradient)
    if choice == '1':
        musor()
    elif choice == '2':
        optimize_internet()
    elif choice == '3':
        reset_internet()
    elif choice == '4':
        disable_services()
    elif choice == '5':
        smartscreen()
    elif choice == '6':
        telemetry()
    elif choice == '7':
        bcdedit_tweaks()
    elif choice == '8':
        optimize_internet2()
    elif choice == '9':
        clear_event_logs()
    elif choice == '10':
        delete_old_windows()
    elif choice == '0':
        exit()
    else:
        os.system('cls')
        print(RED + 'Нет такой команды')
        time.sleep(2)
        main()

if __name__ == '__main__':
    #check_hwid() <-- good guard)))
    main()