EXTENSIONS = {
    'application/gzip': 'GZ',
    'application/json': 'JSON',
    'application/msword': 'DOC',
    'application/pdf': 'PDF', 'image/tiff': 'TIFF',
    'application/rtf': 'RTF',
    'application/vnd.ms-excel': 'XLS',
    'application/vnd.ms-powerpoint': 'PPT',
    'application/vnd.oasis.opendocument.presentation': 'ODP',
    'application/vnd.oasis.opendocument.spreadsheet': 'ODS',
    'application/vnd.oasis.opendocument.text': 'ODT',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'PPTX',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'XLSX',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'DOCX',
    'application/x-bzip2': 'BZ2',
    'application/x-tar': 'TAR',
    'application/xml': 'XML',
    'application/zip': 'ZIP',
    'audio/mpeg': 'MP3',
    'audio/webm': 'WEBA',
    'image/gif': 'GIF',
    'image/jpeg': 'JPG',
    'image/png': 'PNG',
    'image/webp': 'WEBP',
    'text/css': 'CSS',
    'text/csv': 'CSV',
    'text/html': 'HTML',
    'text/javascript': 'JS',
    'text/plain': 'TXT',
    'video/mp4': 'MP4',
    'video/mpeg': 'MPEG',
    'video/webm': 'WEBM',
}
FILE_TYPES = {
    'libraries/zxcvbn.js': 'text/javascript',
    'libraries/zxcvbn.js.map': 'text/javascript',
    'scripts/dokumente.js': 'text/javascript',
    'scripts/konto_einstellungen.js': 'text/javascript',
    'scripts/konto_registrieren.js': 'text/javascript',
    'scripts/navbar.js': 'text/javascript',
    'scripts/lernsets.js': 'text/javascript',
}
GRADES = [
    '-',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
]
LANGUAGES = [
    'de',
    'en',
    'fr',
    'it',
    'es',
    '-'
]
SEARCH_ENGINES = {
    'DuckDuckGo': {
        'url': 'https://duckduckgo.com/?q=%s',
        'recommended': True,
        'favicon': 'https://duckduckgo.com/assets/icons/meta/DDG-iOS-icon_152x152.png'
    },
    'BraveSearch': {
        'url': 'https://search.brave.com/search?q=%s',
        'recommended': True,
        'favicon': 'https://cdn.search.brave.com/serp/v1/static/brand/'
                   'd6a7857f7f3c2d5e1a55d27a8e25b39a31c4c5d093ff479aeb1b99d0faca5c71-favicon.ico'
    },
    'Ecosia': {
        'url': 'https://www.ecosia.org/search?method=index&q=%s',
        'recommended': True,
        'favicon': 'https://cdn-static.ecosia.org/static/icons/favicon.ico'
    },
    'Startpage': {
        'url': 'https://www.startpage.com/sp/search?query=%s',
        'recommended': True,
        'favicon': 'https://www.startpage.com/sp/cdn/favicons/favicon--default.ico'
    },
    'SearXNG': {
        'url': 'https://search.gcomm.ch/search?q=%s&language=de-CH',
        'recommended': True,
        'favicon': 'https://search.gcomm.ch/favicon.ico'
    },
    'WolframAlpha': {
        'url': 'https://www.wolframalpha.com/input?i=%s',
        'recommended': True,
        'favicon': 'https://www.wolframalpha.com/favicon.icoo'
    },
    'Google': {
        'url': 'https://www.google.com/search?q=%s',
        'recommended': False,
        'favicon': 'https://www.google.com/favicon.ico'
    },
    'Bing': {
        'url': 'https://www.bing.com/search?q=%s',
        'recommended': False,
        'favicon': 'https://www.bing.com/favicon.ico'
    },
    'DuckDuckGo[Lite]': {
        'url': 'https://lite.duckduckgo.com/lite/?q=%s',
        'recommended': True,
        'favicon': 'https://lite.duckduckgo.com/assets/icons/meta/DDG-iOS-icon_152x152.png'
    },
    'DuckDuckGo[TOR]': {
        'url': 'https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q=%s',
        'recommended': True,
        'favicon': 'https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/'
                   'assets/icons/meta/DDG-iOS-icon_152x152.png?v=2'
    },
    'Brave Search[TOR]': {
        'url': 'https://search.brave4u7jddbv7cyviptqjc7jusxh72uik7zt6adtckl5f4nwy2v72qd.onion/search?q=%s',
        'recommended': True,
        'favicon': 'https://cdn.search.brave4u7jddbv7cyviptqjc7jusxh72uik7zt6adtckl5f4nwy2v72qd.onion/serp/v1/static/'
                   'brand/8eabe183f0d1f2cb3e2916b7b20c310efd196d740c8cecd341732fcd396fb665-apple-touch-icon.png'
    },
    'SearXNG[TOR]': {
        'url': 'http://searx3aolosaf3urwnhpynlhuokqsgz47si4pzz5hvb7uuzyjncl2tid.onion/search?q=%s',
        'recommended': True,
        'favicon': 'http://searx3aolosaf3urwnhpynlhuokqsgz47si4pzz5hvb7uuzyjncl2tid.onion/'
                   'static/themes/simple/img/favicon.png'
    },
}
SIZE_UNITS = [
    'B',
    'KB',
    'MB',
    'GB',
    'TB',
]
SUBJECTS = {
    '-': 'Keines / Anderes',
    'BG': 'Bildnerisches Gestalten',
    'BI': 'Biologie',
    'BL': 'Begleitetes Lernen',
    'CH': 'Chemie',
    'DE': 'Deutsch',
    'EN': 'Englisch',
    'FR': 'Französisch',
    'GG': 'Geografie',
    'GS': 'Geschichte',
    'HW': 'Hauswirtschaft',
    'IN': 'Informatik',
    'KS': 'Klassenstunde',
    'MA': 'Mathematik',
    'MU': 'Musik',
    'NT': 'Natur & Technik',
    'PB': 'Politische Bildung',
    'PH': 'Philosophie',
    'PS': 'Physik',
    'RE': 'Religionskunde & Ethik',
    'SP': 'Sport',
    'TG': 'Technisches Gestalten',
    'WR': 'Wirtschaft & Recht',
    'SAM': 'Schwerpunktfach Anwendungen der Mathematik',
    'SPS': 'Schwerpunktfach Physik',
    'SBI': 'Schwerpunktfach Biologie',
    'SCH': 'Schwerpunktfach Chemie',
    'SBG': 'Schwerpunktfach Bildnerisches Gestalten',
    'SES': 'Schwerpunktfach Spanisch',
    'SIT': 'Schwerpunktfach Italienisch',
    'SMU': 'Schwerpunktfach Musik',
    'SWR': 'Schwerpunktfach Wirtschaft & Recht',
    'EAM': 'Ergänzungsfach Anwendungen der Mathematik',
    'EBG': 'Ergänzungsfach Bildnerisches Gestalten',
    'EBI': 'Ergänzungsfach Biologie',
    'ECH': 'Ergänzungsfach Chemie',
    'EGG': 'Ergänzungsfach Geografie',
    'EGS': 'Ergänzungsfach Geschichte',
    'EIN': 'Ergänzungsfach Informatik',
    'EMU': 'Ergänzungsfach Musik',
    'EPH': 'Ergänzungsfach Philosophie',
    'EPP': 'Ergänzungsfach Pädagogik & Psychologie',
    'EPS': 'Ergänzungsfach Physik',
    'ERE': 'Ergänzungsfach Religionskunde & Ethik',
    'ESP': 'Ergänzungsfach Sport',
    'EWR': 'Ergänzungsfach Wirtschaft & Recht',
    'F': 'Freifach',
}
THEMES = {
    'hell': {
        'bg': '#ffffff',
        'fg': '#000000',
        'navbar-bg': '#eeeeee',
        'navbar-fg': '#000000',
        'navbar-hover': '#ffffff',
        'footer-bg': '#dddddd',
        'footer-fg': '#000000',
        'footer-a': '#68c4ff',
        'footer-a-hover': '#539dcb',
        'root-query': '#777777',
        'box-li-bg': '#ffffff',
        'box-li-border': '#777777',
        'error-fg': '#ff2222',
    },
}
