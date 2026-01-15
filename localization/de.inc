<?php

/**
 * Localizations for the Kolab 2-Factor-Auth plugin
 *
 * Copyright (C) 2015, Kolab Systems AG
 *
 * For translation see https://www.transifex.com/projects/p/kolab/resource/kolab_2fa/
 */

$labels['factor'] = 'Faktor';
$labels['secret'] = 'Geheimer Schlüssel';
$labels['created'] = 'Erstellt';
$labels['remove'] = 'Entfernen';
$labels['continue'] = 'Weiter';

$labels['settingslist'] = 'Mehr-Faktor Anmeldung';
$labels['settingstitle'] = 'Authentizierungsfaktoren';

$labels['totp'] = 'Mobile App (TOTP)';
$labels['hotp'] = 'Mobile App (HOTP)';
$labels['yubikey'] = 'Yubikey';
$labels['webauthn'] = 'Security Key';

$labels['or'] = 'oder';
$labels['yes'] = 'Ja';
$labels['no'] = 'Nein';
$labels['again'] = 'erneut versuchen';

$labels['label'] = 'Name';
$labels['qrcode'] = 'QR Code';
$labels['showqrcode'] = 'zeige QR Code';
$labels['qrcodeexplaintotp'] = 'Scanne den QR code unten mit deiner Authentifizierungs-App';
$labels['qrcodeexplainhotp'] = 'Scanne den QR code unten mit deiner Authentifizierungs-App';

$labels['yubikeyid'] = 'Deine YubiKey ID';
$labels['yubikeyidexplainyubikey'] = 'Drücke die Taste auf dem YubiKey und sende die generierte Zeichenfolge';

$labels["invalidauthenticatorresponse"] = "Ungültige Authentifikator Antwort";
$labels["invaliddatainup"] = "Ungültige Daten in Nutzer:innen Profil.";
$labels["invalidsessiondata"] = "Ungültige Sitzungsdaten.";
$labels["invalidauthenticatordata"] = "Ungültige Authentifikator Daten";


$labels['factorforcedinfo'] = "Du musst 2FA einrichten, um fortzufahren, indem du unten einen Authentifizierungsfaktor hinzufügst.";
$labels['addfactor'] = 'Authentifizierungsfaktor hinzufügen';
$labels['testfactor'] = 'Teste diesen Faktor';
$labels['verifycode'] = 'Verfiziere Code';
$labels['verifycodeexplaintotp'] = 'Nachdem du den QR-Code gescannt hast, gebe den 6-stelligen Bestätigungscode ein, der von der Authentifizierungs-App generiert wurde.';
$labels['verifycodeexplainhotp'] = 'Nachdem du den QR-Code gescannt hast, gebe den 6-stelligen Bestätigungscode ein, der von der Authentifizierungs-App generiert wurde.';

$labels['loginexpired'] = 'Anmeldeanfrage abgelaufen! Bitte versuche es erneut.';
$labels['authremoveconfirm'] = 'Möchtest Du diesen Authentifizierungsfaktor wirklich aus Deinem Konto entfernen?';
$labels['verifycodemissing'] = 'Bitte gib den Bestätigungscode von deinem Gerät ein.';

$labels['factorsavesuccess'] = 'Authentifizierungsfaktor erfolgreich gespeichert';
$labels['factorremovesuccess'] = 'Authentifizierungsfaktor erfolgreich entfernt';
$labels['factorsaveerror'] = 'Speichern der Authentifizierungsfaktoreinstellungen fehlgeschlagen';
$labels['codeverificationpassed'] = 'Codeüberprüfung für $method erfolgreich';
$labels['codeverificationfailed'] = 'Codeüberprüfung für $method fehlgeschalgen';

$labels['highsecurityrequired'] = 'Zusätzliche Überprüfung erforderlich';
$labels['highsecuritydialog'] = 'Um dein Konto vor Sicherheitsbedrohungen wie Sitzungsdiebstahl oder unbefugtem Zugriff auf deine Daten zu schützen, müsst Du Deine Anmeldedaten mit einem zusätzlichen Authentifizierungsfaktor bestätigen:';
$labels['enterhighsecurity'] = 'Bestätigen';
