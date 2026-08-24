@echo off
title NestTrace v5.1 EXE Builder
echo =========================================
echo NestTrace v5.1 EXE Olusturucu Baslatiliyor...
echo =========================================
echo.
echo Gerekli kutuphaneler yukleniyor (Pip)...
pip install -r requirements.txt
pip install pyinstaller

echo.
echo EXE dosyasi olusturuluyor, lutfen birkac dakika bekleyin...
pyinstaller --onefile --name "NestTrace" nesttrace.py

echo.
echo Islem Tamamlandi!
echo.
echo Proje klasorunuzdeki 'dist' (distribution) klasoru icerisinde 
echo NestTrace.exe dosyasini bulabilirsiniz.
pause
