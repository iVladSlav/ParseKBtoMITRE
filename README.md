# ParseKBtoMITRE
Скрипт для парсинга распакованного KB пакета с коробочными правилами Positive Technologies

Перед началом работы убедитесь, что Вы:
- выгрузили необходимые пакеты экспертизы из KB MP SIEM в формате .kb (Для импорта в другую Knowledge Base)
- распаковали пакеты .kb с помощью kbtools (это можно сделать через расширение для VS Code)
- скачали страничку https://attack.mitre.org/ с матрицей ATT&CK Matrix for Enterprise
- установили зависимости из requirements.txt

Все готово к запуску, следуйте инструкциям в командной строке и Вас все получится!
По умолчангию:
- путь до распакованной KB: D:/KB for VS MP SIEM/_KB_for_VS/packages
- путь до файла со страничкой https://attack.mitre.org/  C:/Users/UserName/Desktop/Matrix.html
- путь к файлу exel со всеми корреляционными правилами C:/Users/UserName/Desktop/ParseToMITRE/correlations.xlsx



Пример таблицы с парсингом KB
![image](https://github.com/iVladSlav/ParseKBtoMITRE/assets/71531115/4ba53b70-d87a-4814-a4c9-7f7ec2c5a302)

Пример итогового маппинга правил корреляций на матрицу ATT&CK Matrix for Enterprise
![image](https://github.com/iVladSlav/ParseKBtoMITRE/assets/71531115/38dce0bd-8555-4462-894e-acc90927cfea)

Результат успешной работы скрипта
![image](https://github.com/iVladSlav/ParseKBtoMITRE/assets/71531115/1abba4bc-bbaf-4cc2-9189-ebaaa427d822)


