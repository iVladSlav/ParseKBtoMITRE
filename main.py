import json
import pandas as pd
from collections import OrderedDict
import re
import os
import yaml
import markdown

def ParseKB(directory):
    files = os.listdir(directory)
    correlatons = []
    descript = []
    packege = []
    technics = []
    tactics = []
    for i in files:
        print('> ' + i + ' parsing')
        # парсинг корреляций, описаний и пакетов
        tmpdir = directory + "/" + i + "/correlation_rules"
        tmpdirfortechnics = directory + "/" + i + "/_meta/i18n/description_ru.md"
        try:
            tmpfiles = os.listdir(tmpdir)
            for j in tmpfiles:
                corrdir = tmpdir + "/" + j + "/i18n/i18n_ru.yaml"
                with open(corrdir, 'r', encoding="utf-8") as file:
                    prime_service = yaml.safe_load(file)
                tmpdescr = prime_service['Description']
                correlatons.append(j)
                descript.append(tmpdescr)
                packege.append(i)
                if j == 'Shadow_Screen_save':
                    j = 'Shadow_Screen_saves'
                # парсинг Техник и Тактик
                try:
                    with open(tmpdirfortechnics, 'r', encoding="utf-8") as mdfile:
                        markdown_string = mdfile.read()
                    tmpfile = markdown.markdown(markdown_string)
                    if j == 'SharPersist_Usage' or j == 'SharpKatz_Usage' or j == 'SilentHound_AD_Enumeration' or j == 'Suspicious_BYOVKD_Driver_Loaded' or j == 'Windows_Webshell_created':
                        technics.append('—')
                        tactics.append('—')
                    elif tmpfile.find(j) == -1:
                        technics.append('—')
                        tactics.append('—')
                    elif tmpfile.find('Тактика</span>') != -1 and tmpfile.find('Техника</span>') != -1:
                        regex2 = re.compile(j + r'[‎]?\s?— .+\n.+\n\n(.*)</span>\n.+\n\n(.*)</span>')
                        matcher = regex2.search(tmpfile, re.IGNORECASE)
                        if matcher == None:
                            regex2 = re.compile(j + r' — .+\n\n.+\n\n(.*)</span>\n.+\n\n(.*)</span>')
                            matcher = regex2.search(tmpfile, re.IGNORECASE)
                            if matcher == None:
                                regex2 = re.compile(j + r' — .+\n\n.+\n.+\n\n(.*)</span>\n.+\n\n(.*)</span>')
                                matcher = regex2.search(tmpfile, re.IGNORECASE)
                                if matcher == None:
                                    regex2 = re.compile(j + r' — .+\n\n.+\n.+\n.+\n\n(.*)</span>\n.+\n\n(.*)</span>')
                                    matcher = regex2.search(tmpfile, re.IGNORECASE)
                                    if matcher == None:
                                        regex2 = re.compile(
                                            j + r' — .+\n\n.+\n.+\n.+\n.+\n\n(.*)</span>\n.+\n\n(.*)</span>')
                                        matcher = regex2.search(tmpfile, re.IGNORECASE)
                                        if matcher == None:
                                            regex1 = re.compile(j + r'<sup>.+\n.+\n\n(.*)</span>\n.+\n\n(.*)</span>')
                                            matcher = regex1.search(tmpfile, re.IGNORECASE)
                        tactics.append(matcher.group(1))
                        technics.append(matcher.group(2))
                    elif tmpfile.find('Тактика</span>') != -1:
                        regex3 = re.compile(j + r'[‎]? — .+\n.+\n\n(.*)</span>')
                        matcher = regex3.search(tmpfile, re.IGNORECASE)
                        tactics.append(matcher.group(1))
                        technics.append('—')
                    elif tmpfile.find('Техника</span>') != -1:
                        regex1 = re.compile(j + r'[‎]? — .+\n.+\n\n(.*)</span>')
                        matcher = regex1.search(tmpfile, re.IGNORECASE)
                        if matcher == None:
                            regex1 = re.compile(j + r'<sup>.+\n.+\n\n(.*)</span>')
                            matcher = regex1.search(tmpfile, re.IGNORECASE)
                        technics.append(matcher.group(1))
                        tactics.append('—')
                    else:
                        technics.append('—')
                        tactics.append('—')
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)
        else:
            print('> DONE')
    df = pd.DataFrame({'Correlation_Name': correlatons, 'Tactic': tactics, 'Techniques': technics, 'Description': descript, 'Package': packege})
    df.to_excel('./correlations.xlsx', index=False)

def MapingMITRE(file,fileexel):
    with open(file, encoding='utf-8') as f:
        html = f.read()
    regex = re.compile(r'<a href="https://attack.mitre.org/techniques/(T\d+)/(\d+).+>(.*)</a>')
    matcher = regex.findall(html, re.IGNORECASE)
    spisok = []
    for i in range(0, int(len(matcher))):
        tmp = matcher[i][0] + '.' + matcher[i][1] + '!' + matcher[i][2]
        spisok.append(tmp)
    spisok[:] = list(OrderedDict.fromkeys(spisok))
    regex2 = re.compile(r'<a href="https://attack.mitre.org/techniques/(T\d+).+>(.*)&')
    matcher2 = regex2.findall(html, re.IGNORECASE)
    spisok2 = []
    for i in range(0, int(len(matcher2))):
        tmp = matcher2[i][0] + '!' + matcher2[i][1]
        spisok2.append(tmp)
    spisok2[:] = list(OrderedDict.fromkeys(spisok2))
    regex3 = re.compile(r'<a href="https://attack.mitre.org/techniques/(T\d+)".*">([0-9a-zA-Z\s/-]*)</a>\n')
    matcher3 = regex3.findall(html, re.IGNORECASE)
    spisok3 = []
    for i in range(0, int(len(matcher3))):
        tmp = matcher3[i][0] + '!' + matcher3[i][1]
        spisok3.append(tmp)
    spisok3[:] = list(OrderedDict.fromkeys(spisok3))

    checkerbook = []
    for j in range(0, int(len(spisok))):
        checkerbook.append(spisok[j].split('!'))
        # print(spisok[j])
    for j in range(0, int(len(spisok2))):
        checkerbook.append(spisok2[j].split('!'))
        # print(spisok2[j])
    for j in range(0, int(len(spisok3))):
        checkerbook.append(spisok3[j].split('!'))
        # print(spisok3[j])
    exel = pd.read_excel(fileexel)
    listof = exel['Techniques'].tolist()
    listof[:] = list(OrderedDict.fromkeys(listof))
    tmplist = []
    for x in range(0, int(len(listof))):
        ttt = listof[x].split(', ')
        for t in range(0, int(len(ttt))):
            tmplist.append(ttt[t])
    tmplistITOG = []
    for z in range(0, int(len(tmplist))):
        www = tmplist[z].split(': ')
        if len(www) > 1:
            tmplistITOG.append(www[1])
        else:
            tmplistITOG.append(www[0])
    for i in range(0,len(tmplistITOG)):
        tmplistITOG[i]=tmplistITOG[i].replace(',','')
        tmplistITOG[i]=tmplistITOG[i].rstrip()
        if tmplistITOG[i]=='Windows Credential Manage':
            tmplistITOG[i]='Windows Credential Manager'
        elif tmplistITOG[i]=='Domain Discovery':
            tmplistITOG[i]='Domain Trust Discovery'
        elif tmplistITOG[i] == 'Command and Scripting Interpreter (Network Device CLI)':
            tmplistITOG[i] = 'Network Device CLI'
        elif tmplistITOG[i] == 'Параметр Ad Hoc Distributed Queries разрешает выполнение нерегламентированных распределенных запросов. Это позволяет пользователям СУБД запрашивать информацию с внешних источников данных и выполнять на них инструкции (например':
            tmplistITOG[i] = '—'
        elif tmplistITOG[i] == 'использовать функции Visual Basic for Applications).':
            tmplistITOG[i] = '—'
    tmplistITOG[:] = list(OrderedDict.fromkeys(tmplistITOG))
    # формируем файл митре
    with open('blank.json', 'r') as blank:
        blank_json=blank.read()
    with open('MITRE.json', 'w') as jsonFILE:
        jsonFILE.write(blank_json)
    with open('MITRE.json', 'r') as jsonFILE:
        matrix_json = jsonFILE.read()
    matrix = json.loads(matrix_json)
    counttech=0
    for i in range(0, int(len(tmplistITOG))):
        for j in range(0, int(len(checkerbook))):
            if tmplistITOG[i].lower() == checkerbook[j][1].lower():
                print('Добавлена техника ' + checkerbook[j][0] + ': ' + checkerbook[j][1])
                counttech+=1
                json_dataReconnaissance = {'techniqueID': checkerbook[j][0], 'tactic': 'reconnaissance',
                                           'color': '#a1d99b', 'comment': '', 'enabled': True, 'metadata': [],
                                           'links': [], 'showSubtechniques': False}
                matrix['techniques'].append(json_dataReconnaissance)
                json_dataResourceDevelopment = {'techniqueID': checkerbook[j][0], 'tactic': 'resource-development',
                                                'color': '#a1d99b', 'comment': '', 'enabled': True, 'metadata': [],
                                                'links': [], 'showSubtechniques': False}
                matrix['techniques'].append(json_dataResourceDevelopment)
                json_dataInitialAccess = {'techniqueID': checkerbook[j][0], 'tactic': 'initial-access',
                                          'color': '#a1d99b', 'comment': '', 'enabled': True, 'metadata': [],
                                          'links': [], 'showSubtechniques': False}
                matrix['techniques'].append(json_dataInitialAccess)
                json_dataExecution = {'techniqueID': checkerbook[j][0], 'tactic': 'execution', 'color': '#a1d99b',
                                      'comment': '', 'enabled': True, 'metadata': [], 'links': [],
                                      'showSubtechniques': False}
                matrix['techniques'].append(json_dataExecution)
                json_dataPersistence = {'techniqueID': checkerbook[j][0], 'tactic': 'persistence', 'color': '#a1d99b',
                                        'comment': '', 'enabled': True, 'metadata': [], 'links': [],
                                        'showSubtechniques': False}
                matrix['techniques'].append(json_dataPersistence)
                json_dataPrivilegeEscalation = {'techniqueID': checkerbook[j][0], 'tactic': 'privilege-escalation',
                                                'color': '#a1d99b', 'comment': '', 'enabled': True, 'metadata': [],
                                                'links': [], 'showSubtechniques': False}
                matrix['techniques'].append(json_dataPrivilegeEscalation)
                json_dataDefenseEvasion = {'techniqueID': checkerbook[j][0], 'tactic': 'defense-evasion',
                                           'color': '#a1d99b', 'comment': '', 'enabled': True, 'metadata': [],
                                           'links': [], 'showSubtechniques': False}
                matrix['techniques'].append(json_dataDefenseEvasion)
                json_dataCredentialAccess = {'techniqueID': checkerbook[j][0], 'tactic': 'credential-access',
                                             'color': '#a1d99b', 'comment': '', 'enabled': True, 'metadata': [],
                                             'links': [], 'showSubtechniques': False}
                matrix['techniques'].append(json_dataCredentialAccess)
                json_dataDiscovery = {'techniqueID': checkerbook[j][0], 'tactic': 'discovery', 'color': '#a1d99b',
                                      'comment': '', 'enabled': True, 'metadata': [], 'links': [],
                                      'showSubtechniques': False}
                matrix['techniques'].append(json_dataDiscovery)
                json_dataLateralMovement = {'techniqueID': checkerbook[j][0], 'tactic': 'lateral-movement',
                                            'color': '#a1d99b', 'comment': '', 'enabled': True, 'metadata': [],
                                            'links': [], 'showSubtechniques': False}
                matrix['techniques'].append(json_dataLateralMovement)
                json_dataCollection = {'techniqueID': checkerbook[j][0], 'tactic': 'collection', 'color': '#a1d99b',
                                       'comment': '', 'enabled': True, 'metadata': [], 'links': [],
                                       'showSubtechniques': False}
                matrix['techniques'].append(json_dataCollection)
                json_dataCommandandControl = {'techniqueID': checkerbook[j][0], 'tactic': 'command-and-control',
                                              'color': '#a1d99b', 'comment': '', 'enabled': True, 'metadata': [],
                                              'links': [], 'showSubtechniques': False}
                matrix['techniques'].append(json_dataCommandandControl)
                json_dataExfiltration = {'techniqueID': checkerbook[j][0], 'tactic': 'exfiltration', 'color': '#a1d99b',
                                         'comment': '', 'enabled': True, 'metadata': [], 'links': [],
                                         'showSubtechniques': False}
                matrix['techniques'].append(json_dataExfiltration)
                json_dataImpact = {'techniqueID': checkerbook[j][0], 'tactic': 'impact', 'color': '#a1d99b',
                                   'comment': '', 'enabled': True, 'metadata': [], 'links': [],
                                   'showSubtechniques': False}
                matrix['techniques'].append(json_dataImpact)
    coutnERR=0
    ListOFcheck = []
    for j in range(0, int(len(checkerbook))):
        ListOFcheck.append(checkerbook[j][1].lower())

    for i in range(0, int(len(tmplistITOG))):
        if tmplistITOG[i].lower() not in ListOFcheck:
            print('Err: Не найдена техника: ' + tmplistITOG[i])
            coutnERR+=1
    with open('MITRE.json', 'w') as jsonFILEout:
        json.dump(matrix, jsonFILEout, ensure_ascii=False, indent=2)
    conclusion = 'Добавлено техник: '+str(counttech)+'\nНе найдено: '+str(coutnERR)
    return conclusion

if __name__ == '__main__':
    WHAT=input('Чего желаете?\n1 - У меня ничего нет, хочу все и сразу\n2 - У меня есть таблица корреляций и техник, хочу сматить ее на MITRE\n')
    if WHAT=='1':
        WHAT2=input('1 - Я прочитал README.md, хочу все по стандарту\n2 - Не-не-не, я укажу свои пути сам\n')
        if WHAT2=='1':
            ParseKB('D:/KB for VS MP SIEM/_KB_for_VS/packages')
            tmpdir = str(os.getcwd())
            x = tmpdir.replace('\\', '/')
            print('Итоговая таблица используемых правил сохранена в: ' + x + '/correlations.xlsx\n')
            FileMITRE = 'C:/Users/UserName/Desktop/Matrix.html'
            FileEXEL = 'C:/Users/UserName/PycharmProjects/ParsePDF/correlations.xlsx'
            print(MapingMITRE(FileMITRE, FileEXEL))
        elif WHAT2=='2':
            DirectoryKB = input('Введите путь до распакованной kb (D:/KB for VS MP SIEM/_KB_for_VS/packages): ')
            ParseKB(DirectoryKB)
            tmpdir = str(os.getcwd())
            x = tmpdir.replace('\\', '/')
            print('Итоговая таблица используемых правил сохранена в: ' + x + '/correlations.xlsx\n')
            FileMITRE = input('Введите путь до html файла страницы https://attack.mitre.org/ (C:/Users/UserName/Desktop/Matrix.html): ')
            FileEXEL = input('Введите путь до итоговой таблицы используемых правил (C:/Users/UserName/PycharmProjects/ParsePDF/correlations.xlsx): ')
            print(MapingMITRE(FileMITRE, FileEXEL))
        else:
            print('Да ты что?')
    elif WHAT=='2':
        WHAT2=input('1 - Я прочитал README.md, хочу все по стандарту\n2 - Не-не-не, я укажу свои пути сам\n')
        if WHAT2=='1':
            FileMITRE = 'C:/Users/UserName/Desktop/Matrix.html'
            FileEXEL = 'C:/Users/UserName/PycharmProjects/ParsePDF/correlations.xlsx'
            print(MapingMITRE(FileMITRE, FileEXEL))
        elif WHAT2=='2':
            FileMITRE = input('Введите путь до html файла страницы https://attack.mitre.org/ (C:/Users/UserName/Desktop/Matrix.html): ')
            FileEXEL = input('Введите путь до итоговой таблицы используемых правил (C:/Users/UserName/PycharmProjects/ParsePDF/correlations.xlsx): ')
            print(MapingMITRE(FileMITRE, FileEXEL))
        else:
            print('Да ты что?')
    else:
        print('Вот это да, такого я не ожидал')




