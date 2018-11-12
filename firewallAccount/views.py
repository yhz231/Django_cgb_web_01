import os
from datetime import date, datetime
from django.contrib.auth.decorators import login_required
import xlrd as xlrd
import xlwt as xlwt
from django.core.cache import cache
from django.db.models import Max
from django.shortcuts import render

# Create your views here.
from DjangoWeb.settings import BASE_DIR
from firewallAccount.models import FWAccount, FWUser, FWResult, FWTempResult


@login_required
def upload(request):
    if request.method == 'GET':
        return render(request, 'firewallAccount/upload.html',{'zonghang_member': True})
    elif request.method == 'POST':
        file = request.FILES.get('acl')
        file.name = 'acl-%s-%s-%s.xlsx' % (datetime.today().year, datetime.today().month, datetime.today().day)
        file_path = os.path.join(BASE_DIR, 'firewallAccount/tempfile/', file.name)
        f = open(file_path, 'wb')
        for chunk in file.chunks():
            f.write(chunk)
        f.close()
        try:
            write_database(file_path)
            create_result(FWResult)
            last_update = '%s-%s-%s' % (datetime.today().year, datetime.today().month, datetime.today().day)
            cache.set('last_update', last_update)
        except:
            return render(request, 'firewallAccount/upload.html', {'upload_success': 'False','zonghang_member': True})
        return render(request, 'firewallAccount/upload.html', {'upload_success': 'True', 'zonghang_member': True})

@login_required
def display(request):
    if request.method == 'POST':
        date_range = request.POST['date_range'].split('-')
        start_date = datetime.strptime('%s-%s-%s' % (date_range[0], date_range[1], date_range[2].rstrip()), '%Y-%m-%d')
        end_date = datetime.strptime('%s-%s-%s' % (date_range[3].lstrip(), date_range[4], date_range[5]), '%Y-%m-%d')
        result = create_result(FWTempResult, start_date, end_date)
        table = FWTempResult
        date_make_sense = request.POST['date_range']
        last_update = cache.get('last_update')
    else:
        last_update = cache.get('last_update')
        date_make_sense = '史前--%s' % last_update
        table = FWResult
        result = True
    if result:
        name_list = table.objects.order_by('-rubbish_acl')
        rubbish_max = max_set(table.objects.all().aggregate(Max('rubbish_acl'))['rubbish_acl__max'])
        any_max = max_set(table.objects.all().aggregate(Max('any_acl'))['any_acl__max'])
        safe_matrix_max = max_set(table.objects.all().aggregate(Max('safe_matrix_acl'))['safe_matrix_acl__max'])
        hight_danger_max = max_set(table.objects.all().aggregate(Max('hight_danger_acl'))['hight_danger_acl__max'])
        no_registered_max = max_set(table.objects.all().aggregate(Max('no_registered_acl'))['no_registered_acl__max'])
        max_data = max_get(rubbish_max, any_max, safe_matrix_max, hight_danger_max, no_registered_max)
        error_message = 'has data'
        return render(request, 'firewallAccount/display.html',
                      {'error_message': error_message, 'date_make_sense': date_make_sense, 'name_list': name_list, 'last_update': last_update,
                       'rubbish_max': rubbish_max, 'any_max': any_max, 'safe_matrix_max': safe_matrix_max,
                       'hight_danger_max': hight_danger_max, 'no_registered_max': no_registered_max,
                       'max_data': max_data, 'zonghang_member': True})
    else:
        error_message = 'no data'
        return render(request, 'firewallAccount/display.html', {'error_message': error_message, 'date_make_sense': date_make_sense, 'zonghang_member': True})
def max_set(value):
    if value < 5:
        value = 5
    return value


def max_get(*args):
    max = 0
    for i in args:
        if max <= i:
            max = i
    return max


def write_database(path):
    workbook = xlrd.open_workbook(path)
    data_sheet = workbook.sheets()[0]
    rowNum = data_sheet.nrows
    colNum = data_sheet.ncols
    FWAccount.objects.all().delete()
    row1 = []
    for col in range(colNum):
        row1.append(data_sheet.cell_value(0, col))
    index_row = row_justify(row1)
    for row in range(1, rowNum):
        row0 = []
        for col in range(colNum):
            row0.append(data_sheet.cell_value(row, col))
        try:
            user = FWUser.objects.get(acs_account=row0[index_row.executor])
        except:
            user = FWUser.objects.get(ad_account=row0[index_row.executor])
        finally:
            exec_date = xlrd.xldate_as_datetime(data_sheet.cell_value(row, index_row.exec_time), workbook.datemode)
            rule = FWAccount(inputer=row0[index_row.inputer], firewall=row0[index_row.firewall], type=row0[index_row.type], firemon_original=row0[index_row.firemon_original], firemon_handle=row0[index_row.firemon_handle], firemon_final=row0[index_row.firemon_final], expire=row0[index_row.expire], executor=user, exec_time=exec_date, order=row0[index_row.order], requirement=row0[index_row.requirement], dissidence=row0[index_row.dissidence], other=row0[index_row.other])
            rule.save()


class row_justify:
    def __init__(self, row):
        for index, i in enumerate(row):
            if i == '录入人':
                self.inputer = index
            elif i == '防火墙':
                self.firewall = index
            elif i == '类型':
                self.type = index
            elif i == 'firemon原始策略':
                self.firemon_original = index
            elif i == 'firemon调整后策略':
                self.firemon_handle = index
            elif i == '审计策略':
                self.firemon_final = index
            elif i == '有效期':
                self.expire = index
            elif i == '执行人':
                self.executor = index
            elif i == '操作时间':
                self.exec_time = index
            elif i == '单号':
                self.order = index
            elif i == '需求概述':
                self.requirement = index
            elif i == '审计结果存在异议':
                self.dissidence = index
            elif i == '备注':
                self.other = index

            

def create_result(table, start_date=datetime.strptime('01-01-1900 00:00', '%m-%d-%Y %H:%M'), end_date=datetime.today()):
    res = FWAccount.objects.filter(exec_time__range=[start_date, end_date])
    if not res:
        return False
    else:
        table.objects.all().delete()
        for i in res:
            user = i.executor.name
            try:
                p1 = table.objects.get(name=user)
            except:
                p1 = table.objects.create(name=user)
            finally:
                if i.type == '垃圾策略':
                    p1.rubbish_acl += 1
                elif i.type == '安全矩阵':
                    p1.safe_matrix_acl += 1
                elif i.type == 'Any策略':
                    p1.any_acl += 1
                elif i.type == '高危策略':
                    p1.hight_danger_acl += 1
                if not i.order:
                    p1.no_registered_acl += 1
            p1.save()
        name_list = table.objects.order_by('-rubbish_acl')
        rank = 1
        for i in name_list:
            i.rank = rank
            i.display_row = rank % 2
            rank += 1
            i.save()
        return True