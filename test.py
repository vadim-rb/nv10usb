from nv10usb import NV10USB
import time

n = NV10USB(serialport='COM15')
if not n.INIT_ERROR:
    print('Синхронизация... ', n.sync())
    print('Установка протокола версии 7 ... ', n.host_protocol_version(7))
    print('Получаем данные о купюрнике ... ', n.setup_request())
    print('Серийный номер ... ', n.get_serial_number())
    print('Опрашиваем ...', n.poll())
    print('Разрешаем прием всех номиналов ... ', n.inhibit_channel())
    print('Включаем ... ', n.enable())
    print(n.display_on())
    while True:
        try:
            poll = n.poll()
            if len(poll) > 0:
                print(poll)
            time.sleep(0.5)
        except KeyboardInterrupt:
            print(n.display_off())
            print('Выключаем ... ',n.disable())
else:
    print('Ошибка ',n.ERROR)
