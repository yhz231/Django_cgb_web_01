from django.shortcuts import render
from django.http import HttpResponse, FileResponse

# Create your views here.
from django.contrib.auth.decorators import login_required
from django.utils.encoding import escape_uri_path


@login_required
def baseLineIndex(request):
    return render(request, 'baseline/baseline.html')

@login_required
def baseLineSubject(request, subject=None):
    template = ['ciscotemplate', 'hwtemplate', 'h3ctemplate', 'mptemplate']
    file_name = ['思科基线配置模板--A(2018.07).xlsx', '华为设备基线配置模板--A(2018.07).xlsx', '华三设备基线配置模板--A(2018.07).xlsx', '迈普设备基线配置模板--A(2018.07).xlsx' ]
    if subject in ['download', 'cisco', 'huawei', 'h3c', 'maipu', 'dot1x', 'hw-nac' ]:
        url = subject
        return render(request, 'baseline/%s.html' % url)
    else:
        for i in range(4):
            if subject == template[i]:
                file = open('templates/baseline/%s.xlsx' % subject, 'rb')
                res = FileResponse(file)
                res["Content-Type"] = "application/octet-stream"
                res["Content-Disposition"] = "attachment;filename={}".format(escape_uri_path(file_name[i]))
                return res

@login_required
def baseLine(request, vendor=None, type=None):
    if vendor and type:
        low_vendor = vendor.lower()
        low_type = type.lower()
        url = '/'.join([low_type])
    else:
        url = 'baseline'
    return render(request, 'baseline/%s.html' % url, {'NTP_KEY': 'cgb100ntp', 'FH3A_KEY': 'cgbfh123'})