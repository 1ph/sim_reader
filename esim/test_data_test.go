package esim

const ReferenceASN1Text = `value1 ProfileElement ::= header : {
  major-version 2,
  minor-version 3,
  profileType "GSMA Generic eUICC Test Profile",
  iccid '89000123456789012341'H,
  eUICC-Mandatory-services {
    usim NULL,
    isim NULL,
    csim NULL,
    usim-test-algorithm NULL,
    ber-tlv NULL,
    get-identity NULL,
    profile-a-x25519 NULL,
    profile-b-p256 NULL
  },
  eUICC-Mandatory-GFSTEList {
    { 2 23 143 1 2 1 },
    { 2 23 143 1 2 3 },
    { 2 23 143 1 2 4 },
    { 2 23 143 1 2 5 },
    { 2 23 143 1 2 7 },
    { 2 23 143 1 2 8 },
    { 2 23 143 1 2 9 },
    { 2 23 143 1 2 10 },
    { 2 23 143 1 2 11 },
    { 2 23 143 1 2 13 },
    { 2 23 143 1 2 14 }
  }
}
value2 ProfileElement ::= mf : {
  mf-header {
    mandated NULL,
    identification 4
  },
  templateID { 2 23 143 1 2 1 },
  mf {
    fileDescriptor : {
      lcsi '05'H,
      securityAttributesReferenced '2F0601'H,
      pinStatusTemplateDO '010A0B'H
    }
  },
  ef-pl {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '2F05'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0604'H,
      efFileSize '06'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '656EFF'H
      }
    }
  },
  ef-iccid {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '2FE2'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0603'H,
      shortEFID '10'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '98001032547698103214'H
  },
  ef-dir {
    fileDescriptor : {
      fileDescriptor '42210021'H,
      fileID '2F00'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0602'H,
      efFileSize '84'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '61144F0CA0000000871002FF49FF058950045553494D'H,
    fillFileOffset : 11,
    fillFileContent : '61144F0CA0000000871004FF49FF058950044953494D'H,
    fillFileOffset : 11,
    fillFileContent : '61184F10A0000003431002F310FFFF89020000FF50044353494D'H
  },
  ef-arr {
    fileDescriptor : {
      fileDescriptor '4221002E'H,
      fileID '2F06'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0602'H,
      efFileSize '02B2'H,
      shortEFID '30'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '80015EA40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 24,
    fillFileContent : '800101900080015AA40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 19,
    fillFileContent : '8001019000800118A40683010A950108'H,
    fillFileOffset : 30,
    fillFileContent : '8001019000800102A4068301019501088401D4A40683010A950108800158A40683010A950108'H,
    fillFileOffset : 8,
    fillFileContent : '800103A406830101950108800118A406830181950108800140A40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 2,
    fillFileContent : '800101A406830101950108800102A406830181950108800158A40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 2,
    fillFileContent : '800103A406830101950108800158A40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 13,
    fillFileContent : '800101A40683010195010880015AA40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 13,
    fillFileContent : '800101A406830101950108800152A40683010A950108'H,
    fillFileOffset : 24,
    fillFileContent : '800101A40683010195010880015AA40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 13,
    fillFileContent : '800103A4068301019501088401D4A40683010A950108800158A40683010A950108'H,
    fillFileOffset : 13,
    fillFileContent : '800101A406830101950108800102A40683010A950108'H,
    fillFileOffset : 24,
    fillFileContent : '800101A406830101950108800102A4068301819501088401D4A40683010A950108800158A40683010A950108'H,
    fillFileOffset : 2,
    fillFileContent : '8001039000800158A40683010A9501088401D4A40683010A950108'H
  },
  ef-umpc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '2F08'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0602'H,
      shortEFID '40'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '3C3C000000'H
  }
}
value3 ProfileElement ::= pukCodes : {
  puk-Header {
    mandated NULL,
    identification 5
  },
  pukCodes {
    {
      keyReference pukAppl1,
      pukValue '3131313131313131'H,
      maxNumOfAttemps-retryNumLeft 170
    },
    {
      keyReference secondPUKAppl1,
      pukValue '3232323232323232'H,
      maxNumOfAttemps-retryNumLeft 170
    }
  }
}
value4 ProfileElement ::= pinCodes : {
  pin-Header {
    mandated NULL,
    identification 2
  },
  pinCodes pinconfig : {
    {
      keyReference pinAppl1,
      pinValue '30303030FFFFFFFF'H,
      unblockingPINReference pukAppl1,
      pinAttributes 6,
      maxNumOfAttemps-retryNumLeft 51
    },
    {
      keyReference adm1,
      pinValue '3535353535353535'H,
      pinAttributes 3,
      maxNumOfAttemps-retryNumLeft 170
    },
    {
      keyReference adm2,
      pinValue '3636363636363636'H,
      pinAttributes 3,
      maxNumOfAttemps-retryNumLeft 170
    }
  }
}
value5 ProfileElement ::= telecom : {
  telecom-header {
    mandated NULL,
    identification 7
  },
  templateID { 2 23 143 1 2 3 },
  df-telecom {
    fileDescriptor : {
      fileID '7F10'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0601'H,
      pinStatusTemplateDO '81010A0B'H
    }
  },
  ef-arr {
    fileDescriptor : {
      fileDescriptor '42210014'H,
      fileID '6F06'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0602'H,
      efFileSize '14'H,
      shortEFID 'B8'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : 'FF'H
  },
  ef-sume {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F54'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0601'H,
      efFileSize '12'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '8500FF'H
      }
    }
  },
  ef-psismsc {
    fileDescriptor : {
      fileDescriptor '42210016'H,
      fileID '6FE5'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0607'H,
      efFileSize '16'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '801474656C3A2B313132323333343435353636373738'H
  },
  df-graphics {
    fileDescriptor : {
      fileID '5F50'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0601'H,
      pinStatusTemplateDO '81010A0B'H
    }
  },
  ef-img {
    fileDescriptor : {
      fileDescriptor '4221000A'H,
      fileID '4F20'H,
      lcsi '05'H,
      securityAttributesReferenced '2F060A'H,
      efFileSize '0A'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-launch-scws {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F01'H,
      lcsi '05'H,
      securityAttributesReferenced '2F060A'H,
      efFileSize '0200'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : 'FF'H
  },
  df-phonebook {
    fileDescriptor : {
      fileID '5F3A'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0601'H,
      pinStatusTemplateDO '81010A0B'H
    }
  },
  ef-pbr {
    fileDescriptor : {
      fileDescriptor '42210064'H,
      fileID '4F30'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0608'H,
      efFileSize '64'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern 'A823C0034F3A0AC1034F1505C5034F0901C6034F4C0BCA034F5109C3034F1904C9034F1606A90FC4034F1102C4034F1307CA034F1408AA12C2034F1203CB034F3D0CC7024F4BC8024F4DFF'H
      }
    }
  },
  ef-psc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F22'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0607'H,
      shortEFID '68'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-cc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F23'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0607'H,
      shortEFID '70'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H,
        repeatPattern '00'H
      }
    }
  },
  ef-puid {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F24'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0607'H,
      shortEFID '78'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H
      }
    },
    fillFileContent : '0002'H
  },
  df-mmss {
    fileDescriptor : {
      fileID '5F3C'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0601'H,
      pinStatusTemplateDO '81010A0B'H
    }
  },
  ef-mlpl {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F20'H,
      lcsi '05'H,
      securityAttributesReferenced '2F060A'H,
      efFileSize '12'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '000901000101010001FF'H
      }
    }
  },
  ef-mspl {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F21'H,
      lcsi '05'H,
      securityAttributesReferenced '2F060A'H,
      efFileSize '12'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '000F0100010101030708020C003E00FF'H
      }
    }
  }
}
value6 ProfileElement ::= pinCodes : {
  pin-Header {
    mandated NULL,
    identification 3
  },
  pinCodes pinconfig : {
    {
      keyReference secondPINAppl1,
      pinValue '39393939FFFFFFFF'H,
      unblockingPINReference secondPUKAppl1,
      pinAttributes 3,
      maxNumOfAttemps-retryNumLeft 51
    }
  }
}
value7 ProfileElement ::= genericFileManagement : {
  gfm-header {
    mandated NULL,
    identification 23
  },
  fileManagementCMD {
    {
      filePath : ''H,
      createFCP : {
        fileDescriptor '4221007C'H,
        fileID '2FFB'H,
        lcsi '05'H,
        securityAttributesReferenced '2F060E'H,
        efFileSize '04D8'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      filePath : '7F10'H,
      createFCP : {
        fileDescriptor '4621001A'H,
        fileID '6F44'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '82'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '00'H
        }
      },
      filePath : '7F105F3A'H,
      createFCP : {
        fileDescriptor '42210002'H,
        fileID '4F09'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '14'H,
        shortEFID '08'H,
        proprietaryEFInfo {
          specialFileInformation '00'H,
          repeatPattern '00'H
        }
      },
      createFCP : {
        fileDescriptor '42210011'H,
        fileID '4F11'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize 'AA'H,
        shortEFID '10'H,
        proprietaryEFInfo {
          specialFileInformation '00'H
        }
      },
      createFCP : {
        fileDescriptor '4221000D'H,
        fileID '4F12'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '82'H,
        shortEFID '18'H,
        proprietaryEFInfo {
          specialFileInformation '40'H,
          fillPattern '00FF'H
        }
      },
      createFCP : {
        fileDescriptor '42210011'H,
        fileID '4F13'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize 'AA'H,
        shortEFID '38'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      createFCP : {
        fileDescriptor '42210028'H,
        fileID '4F14'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '0190'H,
        shortEFID '40'H,
        proprietaryEFInfo {
          specialFileInformation '00'H
        }
      },
      createFCP : {
        fileDescriptor '42210003'H,
        fileID '4F15'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '1E'H,
        shortEFID '28'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      createFCP : {
        fileDescriptor '42210002'H,
        fileID '4F16'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '14'H,
        shortEFID '30'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      fillFileContent : '0001'H,
      fillFileContent : '0002'H,
      fillFileContent : '0000'H,
      fillFileContent : '0000'H,
      fillFileContent : '0000'H,
      fillFileContent : '0000'H,
      fillFileContent : '0000'H,
      fillFileContent : '0000'H,
      fillFileContent : '0000'H,
      fillFileContent : '0000'H,
      createFCP : {
        fileDescriptor '42210014'H,
        fileID '4F19'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize 'C8'H,
        shortEFID '20'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      createFCP : {
        fileDescriptor '4221001C'H,
        fileID '4F3A'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '0118'H,
        shortEFID '50'H,
        proprietaryEFInfo {
          specialFileInformation '00'H
        }
      },
      fillFileContent : '546573746E722E31FFFFFFFFFFFF069194982143F1FFFFFFFFFFFFFF546573746E722E32FFFFFFFFFFFF069194982143F2'H,
      createFCP : {
        fileDescriptor '4221000F'H,
        fileID '4F3D'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '96'H,
        shortEFID '60'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      createFCP : {
        fileDescriptor '4221000A'H,
        fileID '4F4B'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '64'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      createFCP : {
        fileDescriptor '4221000A'H,
        fileID '4F4C'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '64'H,
        shortEFID '58'H,
        proprietaryEFInfo {
          specialFileInformation '40'H,
          repeatPattern '00'H
        }
      },
      createFCP : {
        fileDescriptor '42210014'H,
        fileID '4F4D'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize 'C8'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      createFCP : {
        fileDescriptor '42210028'H,
        fileID '4F51'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        efFileSize '0190'H,
        shortEFID '48'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      filePath : '7F10'H,
      createFCP : {
        fileDescriptor '7821'H,
        fileID '5F3E'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0601'H,
        pinStatusTemplateDO '81010A0B'H
      },
      filePath : '7F105F3E'H,
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F01'H,
        lcsi '05'H,
        securityAttributesReferenced '2F060A'H,
        efFileSize '02'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      fillFileContent : '0700'H,
      createFCP : {
        fileDescriptor '7921'H,
        fileID '4F02'H,
        lcsi '05'H,
        securityAttributesReferenced '2F060A'H,
        efFileSize '0400'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F03'H,
        lcsi '05'H,
        securityAttributesReferenced '2F060A'H,
        efFileSize '64'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F04'H,
        lcsi '05'H,
        securityAttributesReferenced '2F060A'H,
        efFileSize '64'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      filePath : ''H,
      createFCP : {
        fileDescriptor '7821'H,
        fileID '7F66'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0601'H,
        pinStatusTemplateDO '010A0B'H
      },
      filePath : '7F66'H,
      createFCP : {
        fileDescriptor '7821'H,
        fileID '5F40'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0601'H,
        pinStatusTemplateDO '010A0B'H
      },
      filePath : '7F665F40'H,
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F40'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0602'H,
        efFileSize '01'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      fillFileContent : '00'H,
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F41'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0602'H,
        efFileSize '20'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      fillFileContent : '06013C1E3C1E0000000000000000000000000000000000000000000000000000'H,
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F42'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0602'H,
        efFileSize '06'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H,
          repeatPattern '00'H
        }
      },
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F43'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0604'H,
        efFileSize '20'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H,
          repeatPattern '00'H
        }
      },
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F44'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0604'H,
        efFileSize '01'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      fillFileContent : '00'H,
      filePath : ''H,
      createFCP : {
        fileDescriptor '7821'H,
        fileID '7F26'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0601'H,
        pinStatusTemplateDO '010A0B'H
      },
      filePath : '7F26'H,
      createFCP : {
        fileDescriptor '4121'H,
        fileID '6FAB'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0602'H,
        efFileSize '64'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H,
          fillPattern 'A02A8004678112038103070000A21D301B800467811203811353414950322E3311424552544C561153554349FF'H
        }
      }
    }
  }
}
value8 ProfileElement ::= usim : {
  usim-header {
    mandated NULL,
    identification 8
  },
  templateID { 2 23 143 1 2 4 },
  adf-usim {
    fileDescriptor : {
      fileID '7FD0'H,
      dfName 'A0000000871002FF49FF0589'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0601'H,
      pinStatusTemplateDO '81010A0B'H
    }
  },
  ef-imsi {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F07'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060A'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '080910101032547698'H
  },
  ef-arr {
    fileDescriptor : {
      fileDescriptor '42210036'H,
      fileID '6F06'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0608'H,
      efFileSize '032A'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '800101A406830101950108800102A406830181950108800158A40683010A950108'H,
    fillFileOffset : 21,
    fillFileContent : '800103A406830101950108800158A40683010A950108'H,
    fillFileOffset : 32,
    fillFileContent : '800101A40683010195010880015AA40683010A950108'H,
    fillFileOffset : 32,
    fillFileContent : '800101A40683010195010880015AA40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 21,
    fillFileContent : '8001019000800102A4068301019501088401D4A40683010A950108800158A40683010A950108'H,
    fillFileOffset : 16,
    fillFileContent : '800103A4068301019501088401D4A40683010A950108800158A40683010A950108'H,
    fillFileOffset : 21,
    fillFileContent : '800101900080015AA40683010A950108'H,
    fillFileOffset : 38,
    fillFileContent : '800101900080015AA40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 27,
    fillFileContent : '800101A406830101950108800102A4068301819501088401D4A40683010A950108800158A40683010A950108'H,
    fillFileOffset : 10,
    fillFileContent : '800101A40683010195010880011AA40683010A950108'H,
    fillFileOffset : 32,
    fillFileContent : '800101A406830101950108800158A40683010A950108840132A406830101950108800102A010A406830101950108A406830181950108'H,
    fillFileOffset : 0,
    fillFileContent : '800103A40683010A950108'H,
    fillFileOffset : 43,
    fillFileContent : '80015EA40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 32,
    fillFileContent : '80010390008401D4A40683010A950108800158A40683010A950108'H,
    fillFileOffset : 27,
    fillFileContent : '80015FA40683010A9501088401D4A40683010A950108'H
  },
  ef-keys {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F08'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '80'H,
        fillPattern '07FF'H
      }
    }
  },
  ef-keysPS {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F09'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '80'H,
        fillPattern '07FF'H
      }
    }
  },
  ef-hpplmn {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F31'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '00'H
  },
  ef-ust {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F38'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize '11'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '9EFFBF1DFF3E0083410310010400403E39'H
  },
  ef-fdn {
    fileDescriptor : {
      fileDescriptor '4221001C'H,
      fileID '6F3B'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize '8C'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-sms {
    fileDescriptor : {
      fileDescriptor '422100B0'H,
      fileID '6F3C'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize '06E0'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-smsp {
    fileDescriptor : {
      fileDescriptor '4221002A'H,
      fileID '6F42'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize '54'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-smss {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F43'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-spn {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F46'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0607'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '0147534D411154455354FF'H
      }
    }
  },
  ef-est {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F56'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '00'H
  },
  ef-start-hfn {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F5B'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '80'H
      }
    },
    fillFileContent : 'F00000F00000'H
  },
  ef-threshold {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F5C'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        repeatPattern 'FF'H
      }
    }
  },
  ef-psloci {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F73'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '80'H
      }
    },
    fillFileContent : 'FFFFFFFFFFFFFF42F618FFFEFF01'H
  },
  ef-acc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F78'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '0001'H
  },
  ef-fplmn {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F7B'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-loci {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F7E'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '80'H
      }
    },
    fillFileContent : 'FFFFFFFF42F618FFFEFF01'H
  },
  ef-ad {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FAD'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0607'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '80000002'H
  },
  ef-ecc {
    fileDescriptor : {
      fileDescriptor '4221000E'H,
      fileID '6FB7'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0608'H,
      efFileSize '1C'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '11F2FF4575726F20456D6572FF00'H,
    fillFileContent : '19F1FF456D657267656E6379FF00'H
  },
  ef-netpar {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FC4'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize '32'H,
      proprietaryEFInfo {
        specialFileInformation '80'H
      }
    }
  },
  ef-epsloci {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FE3'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H
      }
    },
    fillFileOffset : 12,
    fillFileContent : '000000000001'H
  },
  ef-epsnsc {
    fileDescriptor : {
      fileDescriptor '42210036'H,
      fileID '6FE4'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize '36'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H
      }
    }
  }
}
value9 ProfileElement ::= opt-usim : {
  optusim-header {
    mandated NULL,
    identification 9
  },
  templateID { 2 23 143 1 2 5 },
  ef-li {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F05'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-acmax {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F37'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0609'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-acm {
    fileDescriptor : {
      fileDescriptor '46210003'H,
      fileID '6F39'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060B'H,
      efFileSize '0F'H,
      shortEFID 'E0'H,
      proprietaryEFInfo {
        specialFileInformation '80'H,
        repeatPattern '00'H
      }
    }
  },
  ef-gid1 {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F3E'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize '02'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : 'FFFF'H
  },
  ef-gid2 {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F3F'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize '02'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : 'FFFF'H
  },
  ef-msisdn {
    fileDescriptor : {
      fileDescriptor '42210027'H,
      fileID '6F40'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize '4E'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-puct {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F41'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : 'FFFFFF0000'H
  },
  ef-cbmi {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F45'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize '08'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-cbmid {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F48'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize '08'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-sdn {
    fileDescriptor : {
      fileDescriptor '4221001C'H,
      fileID '6F49'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060A'H,
      efFileSize '8C'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-ext2 {
    fileDescriptor : {
      fileDescriptor '4221000D'H,
      fileID '6F4B'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize '41'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-ext3 {
    fileDescriptor : {
      fileDescriptor '4221000D'H,
      fileID '6F4C'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      efFileSize '41'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-cbmir {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F50'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '10'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-plmnwact {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F60'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize 'AA'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : 'FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000'H
  },
  ef-oplmnwact {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F61'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      efFileSize 'FA'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : 'FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000'H
  },
  ef-hplmnwact {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F62'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      efFileSize 'FA'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : 'FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000FFFFFF0000'H
  },
  ef-dck {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F2C'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  },
  ef-cnl {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F32'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      efFileSize '3C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  },
  ef-smsr {
    fileDescriptor : {
      fileDescriptor '4221001E'H,
      fileID '6F47'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize '012C'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-bdn {
    fileDescriptor : {
      fileDescriptor '42210015'H,
      fileID '6F4D'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize '3F'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  },
  ef-ext5 {
    fileDescriptor : {
      fileDescriptor '4221000D'H,
      fileID '6F4E'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize '41'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-ccp2 {
    fileDescriptor : {
      fileDescriptor '4221000F'H,
      fileID '6F4F'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-acl {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F57'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize 'C8'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-cmi {
    fileDescriptor : {
      fileDescriptor '42210055'H,
      fileID '6F58'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      efFileSize 'AA'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  },
  ef-ici {
    fileDescriptor : {
      fileDescriptor '4621002A'H,
      fileID '6F80'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize 'D2'H,
      proprietaryEFInfo {
        specialFileInformation '80'H,
        fillPattern 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000FF'H
      }
    }
  },
  ef-oci {
    fileDescriptor : {
      fileDescriptor '46210029'H,
      fileID '6F81'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize 'CD'H,
      proprietaryEFInfo {
        specialFileInformation '80'H,
        fillPattern 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FF'H
      }
    }
  },
  ef-ict {
    fileDescriptor : {
      fileDescriptor '46210003'H,
      fileID '6F82'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060B'H,
      efFileSize '1E'H,
      proprietaryEFInfo {
        specialFileInformation '80'H,
        repeatPattern '00'H
      }
    }
  },
  ef-oct {
    fileDescriptor : {
      fileDescriptor '46210003'H,
      fileID '6F83'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060B'H,
      efFileSize '1E'H,
      proprietaryEFInfo {
        specialFileInformation '80'H,
        repeatPattern '00'H
      }
    }
  },
  ef-vgcs {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FB1'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize 'C8'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '21FFFFFF21F3FFFF2143FFFF2143F8FF214319FF215320F92153F1FF2153F2FF2153F3FF2153F4FF2153F5FF2153F6FF2153F7FF2153F8FF2153F9FF0200F0FF0200F1FF0200F2FF0200F3FF0200F4FF0200F5FF0200F6FF0200F7FF0200F8FF0200F9FF0210F0FF6666F0FF6666F1FF6666F2FF666683FF6666F4FF6666F5FF6666F6FF6666F7FF6666F8FF6666F9FF6676F0FF0821F0FF0821F1FF0821F2FF0821F3FF0821F4FF0821F5FF0821F6FF0821F7FF0821F8FF0821F9FF0831F0FF9999F9FF111111F9'H
  },
  ef-vgcss {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FB2'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '150000000000FC'H
  },
  ef-vbs {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FB3'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize 'C8'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '21FFFFFF21F3FFFF2143FFFF2143F8FF214319FF215320F92153F1FF2153F2FF2153F3FF2153F4FF2153F5FF2153F6FF2153F7FF2153F8FF2153F9FF0200F0FF0200F1FF0200F2FF0200F3FF0200F4FF0200F5FF0200F6FF0200F7FF0200F8FF0200F9FF0210F0FF6666F0FF6666F1FF6666F2FF666683FF6666F4FF6666F5FF6666F6FF6666F7FF6666F8FF6666F9FF6676F0FF0821F0FF0821F1FF0821F2FF0821F3FF0821F4FF0821F5FF0821F6FF0821F7FF0821F8FF0821F9FF0831F0FF9999F9FF111111F9'H
  },
  ef-vbss {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FB4'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '150000000000FC'H
  },
  ef-emlpp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FB5'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-aaem {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FB6'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-hiddenkey {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FC3'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-pnn {
    fileDescriptor : {
      fileDescriptor '42210014'H,
      fileID '6FC5'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0608'H,
      efFileSize '64'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : 'FF'H
  },
  ef-opl {
    fileDescriptor : {
      fileDescriptor '42210008'H,
      fileID '6FC6'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0608'H,
      efFileSize '50'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : 'FF'H
  },
  ef-mmsn {
    fileDescriptor : {
      fileDescriptor '42210005'H,
      fileID '6FCE'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '05'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '000000FF'H
      }
    }
  },
  ef-ext8 {
    fileDescriptor : {
      fileDescriptor '4221000D'H,
      fileID '6FCF'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-mmsicp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FD0'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize '17'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-mmsup {
    fileDescriptor : {
      fileDescriptor '4221000A'H,
      fileID '6FD1'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '0A'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-mmsucp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FD2'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0609'H,
      efFileSize '17'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-nia {
    fileDescriptor : {
      fileDescriptor '42210020'H,
      fileID '6FD3'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060A'H,
      efFileSize 'A0'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  },
  ef-vgcsca {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FD4'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize '02'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '0103'H
  },
  ef-vbsca {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FD5'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize '02'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '0103'H
  },
  ef-ehplmn {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FD9'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      efFileSize '1E'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  },
  ef-ehplmnpi {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FDB'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-lrplmnsi {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FDC'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-nasconfig {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FE8'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize '1C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : 'FF'H
  },
  ef-fdnuri {
    fileDescriptor : {
      fileDescriptor '42210014'H,
      fileID '6FED'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize '28'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  },
  ef-sdnuri {
    fileDescriptor : {
      fileDescriptor '42210014'H,
      fileID '6FEF'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      efFileSize '28'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  }
}
value10 ProfileElement ::= pinCodes : {
  pin-Header {
    mandated NULL,
    identification 10
  },
  pinCodes pinconfig : {
    {
      keyReference secondPINAppl1,
      pinValue '39393939FFFFFFFF'H,
      unblockingPINReference secondPUKAppl1,
      pinAttributes 3,
      maxNumOfAttemps-retryNumLeft 51
    }
  }
}
value11 ProfileElement ::= akaParameter : {
  aka-header {
    mandated NULL,
    identification 11
  },
  algoConfiguration algoParameter : {
    algorithmID usim-test-algorithm,
    algorithmOptions '02'H,
    key '000102030405060708090A0B0C0D0E0F'H,
    opc '00000000000000000000000000000000'H,
    rotationConstants '4000204060'H,
    xoringConstants '0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000020000000000000000000000000000000400000000000000000000000000000008'H,
    numberOfKeccak 1
  },
  sqnOptions '02'H,
  sqnDelta '000010000000'H,
  sqnAgeLimit '000010000000'H,
  sqnInit {
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H
  }
}
value12 ProfileElement ::= gsm-access : {
  gsm-access-header {
    mandated NULL,
    identification 12
  },
  templateID { 2 23 143 1 2 7 },
  df-gsm-access {
    fileDescriptor : {
      fileID '5F3B'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060D'H,
      pinStatusTemplateDO '81010A0B'H
    }
  },
  ef-kc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F20'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '80'H
      }
    },
    fillFileOffset : 8,
    fillFileContent : '07'H
  },
  ef-kcgprs {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F52'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      proprietaryEFInfo {
        specialFileInformation '80'H
      }
    },
    fillFileOffset : 8,
    fillFileContent : '07'H
  },
  ef-cpbcch {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F63'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize '14'H,
      proprietaryEFInfo {
        specialFileInformation '80'H
      }
    }
  },
  ef-invscan {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F64'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '00'H
  }
}
value13 ProfileElement ::= df-5gs : {
  df-5gs-header {
    mandated NULL,
    identification 13
  },
  templateID { 2 23 143 1 2 13 },
  df-df-5gs {
    fileDescriptor : {
      fileID '5FC0'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060D'H,
      pinStatusTemplateDO '81010A0B'H
    }
  },
  ef-5gs3gpploci {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F01'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H
      }
    },
    fillFileOffset : 13,
    fillFileContent : '42F61800000001'H
  },
  ef-5gsn3gpploci {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F02'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H
      }
    },
    fillFileOffset : 13,
    fillFileContent : '42F61800000001'H
  },
  ef-5gs3gppnsc {
    fileDescriptor : {
      fileDescriptor '42210039'H,
      fileID '4F03'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '39'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H
      }
    }
  },
  ef-5gsn3gppnsc {
    fileDescriptor : {
      fileDescriptor '42210039'H,
      fileID '4F04'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '39'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H
      }
    }
  },
  ef-5gauthkeys {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F05'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '6E'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H
      }
    }
  },
  ef-uac-aic {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F06'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00000000'H
  },
  ef-suci-calc-info {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F07'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      efFileSize '76'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern 'A0020000FF'H
      }
    }
  },
  ef-opl5g {
    fileDescriptor : {
      fileDescriptor '4221000A'H,
      fileID '4F08'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0608'H,
      efFileSize '32'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  },
  ef-routing-indicator {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F0A'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern 'F0FF'H
      }
    }
  }
}
value14 ProfileElement ::= df-saip : {
  df-saip-header {
    mandated NULL,
    identification 14
  },
  templateID { 2 23 143 1 2 14 },
  df-df-saip {
    fileDescriptor : {
      fileID '5FD0'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060D'H,
      pinStatusTemplateDO '81010A0B'H
    }
  },
  ef-suci-calc-info-usim {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '4F01'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060F'H,
      efFileSize '76'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern 'A0020000FF'H
      }
    }
  }
}
value15 ProfileElement ::= csim : {
  csim-header {
    mandated NULL,
    identification 15
  },
  templateID { 2 23 143 1 2 10 },
  adf-csim {
    fileDescriptor : {
      fileID '7FC0'H,
      dfName 'A0000003431002F310FFFF89020000FF'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0601'H,
      pinStatusTemplateDO '81010A0B'H
    }
  },
  ef-arr {
    fileDescriptor : {
      fileDescriptor '4221002E'H,
      fileID '6F06'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060A'H,
      efFileSize '03F4'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '8001019000'H,
    fillFileOffset : 41,
    fillFileContent : '800101A406830101950108800102A406830181950108800158A40683010A950108'H,
    fillFileOffset : 13,
    fillFileContent : '800103A406830101950108800158A40683010A950108'H,
    fillFileOffset : 24,
    fillFileContent : '800101A40683010195010880015AA40683010A950108'H,
    fillFileOffset : 24,
    fillFileContent : '800101A40683010195010880015AA40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 13,
    fillFileContent : '800103A4068301019501088401D4A40683010A950108800158A40683010A950108'H,
    fillFileOffset : 13,
    fillFileContent : '800101900080015AA40683010A950108'H,
    fillFileOffset : 30,
    fillFileContent : '8001019000800102A4068301019501088401D4A40683010A950108800158A40683010A950108'H,
    fillFileOffset : 8,
    fillFileContent : '800101A406830101950108'H,
    fillFileOffset : 35,
    fillFileContent : '800101900080015AA40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 19,
    fillFileContent : '800103A406830101950108800118A40683010A950108840132A406830101950108'H,
    fillFileOffset : 13,
    fillFileContent : '800103A406830101950108800118A40683010A950108'H,
    fillFileOffset : 24,
    fillFileContent : '800101A406830101950108800102A4068301819501088401D4A40683010A950108800158A40683010A950108'H,
    fillFileOffset : 2,
    fillFileContent : '800152A40683010A950108'H,
    fillFileOffset : 35,
    fillFileContent : '800111A40683010195010880010AA40683010A950108'H,
    fillFileOffset : 24,
    fillFileContent : '800113A406830101950108800108A40683010A950108'H,
    fillFileOffset : 24,
    fillFileContent : '800101A40683010195010880011AA40683010A9501088401D4A40683010A950108'H,
    fillFileOffset : 13,
    fillFileContent : '80011BA40683010A950108'H,
    fillFileOffset : 35,
    fillFileContent : '800101900080011AA40683010A950108'H,
    fillFileOffset : 30,
    fillFileContent : '800101A40683010195010880011AA40683010A950108'H,
    fillFileOffset : 24,
    fillFileContent : '800101900080011AA40683010A9501088401D4A40683010A950108'H
  },
  ef-call-count {
    fileDescriptor : {
      fileDescriptor '46210002'H,
      fileID '6F21'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060B'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H,
        repeatPattern '00'H
      }
    }
  },
  ef-imsi-m {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F22'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060F'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '008D03CB11033480DE03'H
  },
  ef-imsi-t {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F23'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060F'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '008D03CB11033480DE03'H
  },
  ef-tmsi {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F24'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0610'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H
      }
    },
    fillFileContent : '000000000000000000FFFFFFFF000000'H
  },
  ef-ah {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F25'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-aop {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F26'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-aloc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F27'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H,
        repeatPattern '00'H
      }
    }
  },
  ef-cdmahome {
    fileDescriptor : {
      fileDescriptor '42210005'H,
      fileID '6F28'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      efFileSize '64'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : 'E803AE0800'H,
    fillFileContent : 'E803AE0801'H,
    fillFileContent : 'E803AE0803'H,
    fillFileContent : 'E803AE0804'H,
    fillFileContent : 'E803AE0805'H,
    fillFileContent : 'E803AE0806'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H,
    fillFileContent : '0000000000'H
  },
  ef-znregi {
    fileDescriptor : {
      fileDescriptor '42210008'H,
      fileID '6F29'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      efFileSize '38'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H,
        repeatPattern '00'H
      }
    }
  },
  ef-snregi {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F2A'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H
      }
    },
    fillFileContent : '01000000000000'H
  },
  ef-distregi {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F2B'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H,
        repeatPattern '00'H
      }
    }
  },
  ef-accolc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F2C'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0614'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-term {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F2D'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '07'H
  },
  ef-acp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F2F'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '4E014D014E0115'H
  },
  ef-prl {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F30'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0611'H,
      efFileSize '12'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '001200000000400121000280005000006EDB'H
  },
  ef-ruimid {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F31'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize '08'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '0480000000000000'H
  },
  ef-csim-st {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F32'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0611'H,
      efFileSize '0A'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : 'F8F2009C030000000000'H
  },
  ef-spc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F33'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0612'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-otapaspc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F34'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-namlock {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F35'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-ota {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F36'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0611'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '0500020201020303010401000000000000'H
  },
  ef-sp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F37'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '62'H
  },
  ef-esn-meid-me {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F38'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0613'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-li {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F3A'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0608'H,
      efFileSize '04'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '02FF02FF'H
  },
  ef-usgind {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F42'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0614'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '03'H
  },
  ef-ad {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F43'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0615'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-max-prl {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F45'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0614'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00122000'H
  },
  ef-spcs {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F46'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0609'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-mecrp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F55'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-home-tag {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F70'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      efFileSize '0C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-group-tag {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F71'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      efFileSize '0F'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-specific-tag {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F72'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      efFileSize '0F'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  },
  ef-call-prompt {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F73'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      efFileSize '0F'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern '00'H
      }
    }
  }
}
value16 ProfileElement ::= opt-csim : {
  optcsim-header {
    mandated NULL,
    identification 16
  },
  templateID { 2 23 143 1 2 11 },
  ef-ssci {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F2E'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '02'H
  },
  ef-fdn {
    fileDescriptor : {
      fileDescriptor '4221001C'H,
      fileID '6F3B'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060D'H,
      linkPath '7FD06F3B'H
    }
  },
  ef-sms {
    fileDescriptor : {
      fileDescriptor '422100C0'H,
      fileID '6F3C'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '03C0'H,
      proprietaryEFInfo {
        specialFileInformation '80'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-smsp {
    fileDescriptor : {
      fileDescriptor '42210017'H,
      fileID '6F3D'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      efFileSize '17'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H,
        fillPattern '00021002FFFF02FF'H
      }
    }
  },
  ef-smss {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F3E'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '05'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  },
  ef-ssfc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F3F'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '6F'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-spn {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F41'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0607'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '01000144656661756C7420536572766963652050726F7669646572204E616D65FF'H
      }
    }
  },
  ef-mdn {
    fileDescriptor : {
      fileDescriptor '4221000B'H,
      fileID '6F44'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      efFileSize '0B'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '0A21436587A9FFFFFF0A00'H
  },
  ef-ecc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F47'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060A'H,
      efFileSize '0C'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '19F1FF11F2FF'H
      }
    }
  },
  ef-me3gpdopc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F48'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-3gpdopm {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F49'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '01'H
  },
  ef-sipcap {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F4A'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '15084000'H
  },
  ef-mipcap {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F4B'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '1508404200'H
  },
  ef-sipupp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F4C'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      efFileSize '53'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '1710143132333435363738393040727333672E636F6D2010FF'H
      }
    }
  },
  ef-mipupp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F4D'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      efFileSize '93'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '2CCC010133132333435363738393040727333672E636F6D800000007FFFFFFFFFFFFFFF8C00000008600000258FF'H
      }
    }
  },
  ef-sipsp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F4E'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-mipsp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F4F'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '02'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00FF'H
  },
  ef-sippapss {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F50'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '21'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '00FF'H
      }
    }
  },
  ef-hrpdcap {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F56'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '20F880'H
  },
  ef-hrpdupp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F57'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      efFileSize '0E'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '0D0B6162634078797A2E636F6D10'H
  },
  ef-csspr {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F58'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        repeatPattern 'FF'H
      }
    }
  },
  ef-atc {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F59'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-eprl {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F5A'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      efFileSize '81'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00810000030001800004000A040164030B0B04016403F50A040A5808190B040A580C970A0231130B0230C871C00200101F0100C8FFFF00800038E0080000800071E01200101F0100C8FFFF00800038E0180000800071C02200101F0100C8FFFF00808038E0280000808071E00200101F0100C8FFFF00808038E008000080802B6B'H
  },
  ef-bcsmsp {
    fileDescriptor : {
      fileDescriptor '42210002'H,
      fileID '6F5E'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '04'H,
      proprietaryEFInfo {
        specialFileInformation 'C0'H,
        repeatPattern 'FF'H
      }
    }
  },
  ef-mmsn {
    fileDescriptor : {
      fileDescriptor '42210008'H,
      fileID '6F65'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      efFileSize '28'H,
      proprietaryEFInfo {
        specialFileInformation '40'H,
        fillPattern '000000FF'H
      }
    }
  },
  ef-ext8 {
    fileDescriptor : {
      fileDescriptor '4221000D'H,
      fileID '6F66'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      linkPath '7FD06FCF'H
    }
  },
  ef-mmsicp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F67'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      linkPath '7FD06FD0'H
    }
  },
  ef-mmsup {
    fileDescriptor : {
      fileDescriptor '4221000A'H,
      fileID '6F68'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      linkPath '7FD06FD1'H
    }
  },
  ef-mmsucp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F69'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      linkPath '7FD06FD2'H
    }
  },
  ef-3gcik {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F6B'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : 'FF'H
  },
  ef-gid1 {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F6D'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      efFileSize '08'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : 'FF'H
  },
  ef-gid2 {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F6E'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      efFileSize '08'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : 'FF'H
  },
  ef-sf-euimid {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F74'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : 'FF'H
  },
  ef-est {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F75'H,
      lcsi '05'H,
      securityAttributesReferenced '6F060D'H,
      efFileSize '01'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : '00'H
  },
  ef-hidden-key {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F76'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      linkPath '7FD06FC3'H
    }
  },
  ef-sdn {
    fileDescriptor : {
      fileDescriptor '4221001C'H,
      fileID '6F79'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0605'H,
      linkPath '7FD06F49'H
    }
  },
  ef-ext2 {
    fileDescriptor : {
      fileDescriptor '4221000D'H,
      fileID '6F7A'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      linkPath '7FD06F4B'H
    }
  },
  ef-ext3 {
    fileDescriptor : {
      fileDescriptor '4221000D'H,
      fileID '6F7B'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0604'H,
      linkPath '7FD06F4C'H
    }
  },
  ef-ici {
    fileDescriptor : {
      fileDescriptor '4621002A'H,
      fileID '6F7C'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      linkPath '7FD06F80'H
    }
  },
  ef-oci {
    fileDescriptor : {
      fileDescriptor '46210029'H,
      fileID '6F7D'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      linkPath '7FD06F81'H
    }
  },
  ef-ext5 {
    fileDescriptor : {
      fileDescriptor '4221000D'H,
      fileID '6F7E'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      linkPath '7FD06F4E'H
    }
  },
  ef-ccp2 {
    fileDescriptor : {
      fileDescriptor '4221000F'H,
      fileID '6F7F'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      linkPath '7FD06F4F'H
    }
  },
  ef-model {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F81'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0606'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    }
  }
}
value17 ProfileElement ::= pinCodes : {
  pin-Header {
    mandated NULL,
    identification 17
  },
  pinCodes pinconfig : {
    {
      keyReference secondPINAppl1,
      pinValue '39393939FFFFFFFF'H,
      unblockingPINReference secondPUKAppl1,
      pinAttributes 3,
      maxNumOfAttemps-retryNumLeft 51
    }
  }
}
value18 ProfileElement ::= cdmaParameter : {
  cdma-header {
    mandated NULL,
    identification 18
  },
  authenticationKey '00000000FFFFFFFF'H,
  ssd '0123456789ABCDEF0123456789ABCDEF'H,
  hrpdAccessAuthenticationData '8008101820283038404880889098A0A8B0'H,
  simpleIPAuthenticationData '108008101820283038404880889098A0A8B0'H,
  mobileIPAuthenticationData '108008101820283038404880889098A0A8B4004080C1014181C20244044484C5054580'H
}
value19 ProfileElement ::= isim : {
  isim-header {
    mandated NULL,
    identification 19
  },
  templateID { 2 23 143 1 2 8 },
  adf-isim {
    fileDescriptor : {
      fileID '7FB0'H,
      dfName 'A0000000871004FF49FF0589'H,
      lcsi '05'H,
      securityAttributesReferenced '2F0601'H,
      pinStatusTemplateDO '81010A0B'H
    }
  },
  ef-impi {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F02'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize '20'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '801D30303130313031323334353637383940746573742E336770702E636F6DFF'H
  },
  ef-impu {
    fileDescriptor : {
      fileDescriptor '42210040'H,
      fileID '6F04'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize 'C0'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '80357369703A30303130313031323334353637383940696D732E6D6E633030312E6D63633030312E336770706E6574776F726B2E6F7267'H,
    fillFileOffset : 9,
    fillFileContent : '801E7369703A2B313132333435363738393040746573742E336770702E636F6D'H,
    fillFileOffset : 32,
    fillFileContent : '80167369703A7573657240746573742E336770702E636F6D'H
  },
  ef-domain {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F03'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize '20'H,
      proprietaryEFInfo {
        specialFileInformation '00'H,
        fillPattern '800D746573742E336770702E636F6DFF'H
      }
    }
  },
  ef-ist {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6F07'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize '07'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '01001000000000'H
  },
  ef-ad {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FAD'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '800002'H
  },
  ef-arr {
    fileDescriptor : {
      fileDescriptor '42210023'H,
      fileID '6F06'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0603'H,
      efFileSize '8C'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    },
    fillFileContent : '800101A40683010195010880015AA40683010A9501088401D4A40683010A950108FFFF800103A4068301019501088401D4A40683010A950108800158A40683010A950108FFFF800101900080015AA40683010A9501088401D4A40683010A950108'H
  }
}
value20 ProfileElement ::= opt-isim : {
  optisim-header {
    mandated NULL,
    identification 20
  },
  templateID { 2 23 143 1 2 9 },
  ef-pcscf {
    fileDescriptor : {
      fileDescriptor '42210020'H,
      fileID '6F09'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize '60'H,
      proprietaryEFInfo {
        specialFileInformation '40'H
      }
    },
    fillFileContent : 'FF'H
  },
  ef-gbabp {
    fileDescriptor : {
      fileDescriptor '4121'H,
      fileID '6FD5'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0602'H,
      efFileSize '64'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  },
  ef-gbanl {
    fileDescriptor : {
      fileDescriptor '42210064'H,
      fileID '6FD7'H,
      lcsi '05'H,
      securityAttributesReferenced '6F0601'H,
      efFileSize '01F4'H,
      proprietaryEFInfo {
        specialFileInformation '00'H
      }
    }
  }
}
value21 ProfileElement ::= pinCodes : {
  pin-Header {
    mandated NULL,
    identification 21
  },
  pinCodes pinconfig : {
    {
      keyReference secondPINAppl1,
      pinValue '39393939FFFFFFFF'H,
      unblockingPINReference secondPUKAppl1,
      pinAttributes 3,
      maxNumOfAttemps-retryNumLeft 51
    }
  }
}
value22 ProfileElement ::= akaParameter : {
  aka-header {
    mandated NULL,
    identification 22
  },
  algoConfiguration algoParameter : {
    algorithmID usim-test-algorithm,
    algorithmOptions '02'H,
    key '000102030405060708090A0B0C0D0E0F'H,
    opc '00000000000000000000000000000000'H,
    rotationConstants '4000204060'H,
    xoringConstants '0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000020000000000000000000000000000000400000000000000000000000000000008'H,
    numberOfKeccak 1
  },
  sqnOptions '02'H,
  sqnDelta '000010000000'H,
  sqnAgeLimit '000010000000'H,
  sqnInit {
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H,
    '000000000000'H
  }
}
value23 ProfileElement ::= genericFileManagement : {
  gfm-header {
    mandated NULL,
    identification 24
  },
  fileManagementCMD {
    {
      filePath : '7FD0'H,
      createFCP : {
        fileDescriptor '7821'H,
        fileID '5F50'H,
        lcsi '05'H,
        securityAttributesReferenced '6F060D'H,
        pinStatusTemplateDO '81010A0B'H
      },
      filePath : '7FD05F50'H,
      createFCP : {
        fileDescriptor '4221003B'H,
        fileID '4F81'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0606'H,
        efFileSize '0127'H,
        proprietaryEFInfo {
          specialFileInformation '00'H
        }
      },
      createFCP : {
        fileDescriptor '42210064'H,
        fileID '4F82'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0606'H,
        efFileSize '012C'H,
        proprietaryEFInfo {
          specialFileInformation '00'H
        }
      },
      createFCP : {
        fileDescriptor '42210064'H,
        fileID '4F83'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0606'H,
        efFileSize '012C'H,
        proprietaryEFInfo {
          specialFileInformation '00'H
        }
      },
      createFCP : {
        fileDescriptor '42210014'H,
        fileID '4F84'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0604'H,
        efFileSize '14'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      createFCP : {
        fileDescriptor '42210014'H,
        fileID '4F85'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0604'H,
        efFileSize '14'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      createFCP : {
        fileDescriptor '42210003'H,
        fileID '4F86'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0604'H,
        efFileSize '03'H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      filePath : '7FD0'H,
      createFCP : {
        fileDescriptor '7821'H,
        fileID '7F66'H,
        lcsi '05'H,
        securityAttributesReferenced '6F060D'H,
        pinStatusTemplateDO '81010A0B'H
      },
      filePath : '7FD07F66'H,
      createFCP : {
        fileDescriptor '7821'H,
        fileID '5F40'H,
        lcsi '05'H,
        securityAttributesReferenced '6F060D'H,
        pinStatusTemplateDO '81010A0B'H
      },
      filePath : '7FD05FC0'H,
      createFCP : {
        fileDescriptor '7921'H,
        fileID '4F0B'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0604'H,
        efFileSize '0400'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      filePath : '7FD0'H,
      createFCP : {
        fileDescriptor '7921'H,
        fileID '6FFE'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0604'H,
        efFileSize '0400'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      },
      filePath : '7FB0'H,
      createFCP : {
        fileDescriptor '7921'H,
        fileID '6FFE'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0604'H,
        efFileSize '0400'H,
        shortEFID ''H,
        proprietaryEFInfo {
          specialFileInformation '40'H
        }
      }
    }
  }
}
value24 ProfileElement ::= genericFileManagement : {
  gfm-header {
    mandated NULL,
    identification 25
  },
  fileManagementCMD {
    {
      filePath : '7F10'H,
      createFCP : {
        fileDescriptor '4221001C'H,
        fileID '6F3A'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0605'H,
        shortEFID ''H,
        linkPath '7F105F3A4F3A'H
      },
      createFCP : {
        fileDescriptor '4221001C'H,
        fileID '6F3B'H,
        lcsi '05'H,
        securityAttributesReferenced '2F060D'H,
        shortEFID ''H,
        linkPath '7FD06F3B'H
      },
      createFCP : {
        fileDescriptor '422100B0'H,
        fileID '6F3C'H,
        lcsi '05'H,
        securityAttributesReferenced '2F060B'H,
        shortEFID ''H,
        linkPath '7FD06F3C'H
      },
      createFCP : {
        fileDescriptor '42210027'H,
        fileID '6F40'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0608'H,
        shortEFID ''H,
        linkPath '7FD06F40'H
      },
      createFCP : {
        fileDescriptor '4221002A'H,
        fileID '6F42'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        shortEFID ''H,
        linkPath '7FD06F42'H
      },
      createFCP : {
        fileDescriptor '4121'H,
        fileID '6F43'H,
        lcsi '05'H,
        securityAttributesReferenced '2F060B'H,
        shortEFID ''H,
        linkPath '7FD06F43'H
      },
      createFCP : {
        fileDescriptor '4221001E'H,
        fileID '6F47'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        shortEFID ''H,
        linkPath '7FD06F47'H
      },
      createFCP : {
        fileDescriptor '4221001C'H,
        fileID '6F49'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0608'H,
        shortEFID ''H,
        linkPath '7FD06F49'H
      },
      createFCP : {
        fileDescriptor '4221000D'H,
        fileID '6F4A'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0607'H,
        shortEFID ''H,
        linkPath '7F105F3A4F12'H
      },
      createFCP : {
        fileDescriptor '4221000D'H,
        fileID '6F4B'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0606'H,
        shortEFID ''H,
        linkPath '7FD06F4B'H
      },
      createFCP : {
        fileDescriptor '4221000D'H,
        fileID '6F4C'H,
        lcsi '05'H,
        securityAttributesReferenced '2F0608'H,
        shortEFID ''H,
        linkPath '7FD06F4C'H
      },
      filePath : '7FD07F665F40'H,
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F40'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0608'H,
        shortEFID ''H,
        linkPath '7F665F404F40'H
      },
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F41'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0608'H,
        shortEFID ''H,
        linkPath '7F665F404F41'H
      },
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F42'H,
        lcsi '05'H,
        securityAttributesReferenced '6F0608'H,
        shortEFID ''H,
        linkPath '7F665F404F42'H
      },
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F43'H,
        lcsi '05'H,
        securityAttributesReferenced '6F060E'H,
        shortEFID ''H,
        linkPath '7F665F404F43'H
      },
      createFCP : {
        fileDescriptor '4121'H,
        fileID '4F44'H,
        lcsi '05'H,
        securityAttributesReferenced '6F060E'H,
        shortEFID ''H,
        linkPath '7F665F404F44'H
      }
    }
  }
}
value25 ProfileElement ::= securityDomain : {
  sd-Header {
    mandated NULL,
    identification 26
  },
  instance {
    applicationLoadPackageAID 'A0000001515350'H,
    classAID 'A000000151535041'H,
    instanceAID 'A000000151000000'H,
    applicationPrivileges '82DC00'H,
    lifeCycleState '0F'H,
    applicationSpecificParametersC9 '810280008201F08301F08701F0'H,
    applicationParameters {
      uiccToolkitApplicationSpecificParametersField '010000000002010206B2010000000000'H
    }
  },
  keyList {
    {
      keyUsageQualifier '18'H,
      keyAccess '00'H,
      keyIdentifier '01'H,
      keyVersionNumber '01'H,
      keyCompontents {
        {
          keyType '80'H,
          keyData '000102030405060708090A0B0C0D0E0F'H,
          macLength 8
        }
      }
    },
    {
      keyUsageQualifier '14'H,
      keyAccess '00'H,
      keyIdentifier '02'H,
      keyVersionNumber '01'H,
      keyCompontents {
        {
          keyType '80'H,
          keyData '000102030405060708090A0B0C0D0E0F'H,
          macLength 8
        }
      }
    },
    {
      keyUsageQualifier '48'H,
      keyAccess '00'H,
      keyIdentifier '03'H,
      keyVersionNumber '01'H,
      keyCompontents {
        {
          keyType '80'H,
          keyData '000102030405060708090A0B0C0D0E0F'H,
          macLength 8
        }
      }
    },
    {
      keyUsageQualifier '18'H,
      keyAccess '00'H,
      keyIdentifier '01'H,
      keyVersionNumber '02'H,
      keyCompontents {
        {
          keyType '88'H,
          keyData '000102030405060708090A0B0C0D0E0F'H,
          macLength 8
        }
      }
    },
    {
      keyUsageQualifier '14'H,
      keyAccess '00'H,
      keyIdentifier '02'H,
      keyVersionNumber '02'H,
      keyCompontents {
        {
          keyType '88'H,
          keyData '000102030405060708090A0B0C0D0E0F'H,
          macLength 8
        }
      }
    },
    {
      keyUsageQualifier '48'H,
      keyAccess '00'H,
      keyIdentifier '03'H,
      keyVersionNumber '02'H,
      keyCompontents {
        {
          keyType '88'H,
          keyData '000102030405060708090A0B0C0D0E0F'H,
          macLength 8
        }
      }
    }
  },
  sdPersoData {
    '0070326630732E06072A864886FC6B01600B06092A864886FC6B020202630906072A864886FC6B03640B06092A864886FC6B048000'H
  }
}
value26 ProfileElement ::= rfm : {
  rfm-header {
    mandated NULL,
    identification 27
  },
  instanceAID 'A00000055910100001'H,
  tarList {
    'B00120'H
  },
  minimumSecurityLevel '02'H,
  uiccAccessDomain '00'H,
  uiccAdminAccessDomain '00'H
}
value27 ProfileElement ::= rfm : {
  rfm-header {
    mandated NULL,
    identification 28
  },
  instanceAID 'A00000055910100002'H,
  tarList {
    'B00140'H
  },
  minimumSecurityLevel '02'H,
  uiccAccessDomain '00'H,
  uiccAdminAccessDomain '00'H,
  adfRFMAccess {
    adfAID 'A0000000871002FF49FF0589'H,
    adfAccessDomain '00'H,
    adfAdminAccessDomain '00'H
  }
}
value28 ProfileElement ::= rfm : {
  rfm-header {
    mandated NULL,
    identification 29
  },
  instanceAID 'A00000055910100003'H,
  tarList {
    'B00141'H
  },
  minimumSecurityLevel '02'H,
  uiccAccessDomain '00'H,
  uiccAdminAccessDomain '00'H,
  adfRFMAccess {
    adfAID 'A0000000871004FF49FF0589'H,
    adfAccessDomain '00'H,
    adfAdminAccessDomain '00'H
  }
}
value29 ProfileElement ::= rfm : {
  rfm-header {
    mandated NULL,
    identification 30
  },
  instanceAID 'A00000055910100004'H,
  tarList {
    'B00142'H
  },
  minimumSecurityLevel '02'H,
  uiccAccessDomain '00'H,
  uiccAdminAccessDomain '00'H,
  adfRFMAccess {
    adfAID 'A0000003431002F310FFFF89020000FF'H,
    adfAccessDomain '00'H,
    adfAdminAccessDomain '00'H
  }
}
value30 ProfileElement ::= end : {
  end-header {
    mandated NULL,
    identification 31
  }
}
`

const ReferenceBinaryDERHex = "a0819f800102810103821f47534d412047656e65726963206555494343205465" +
	"73742050726f66696c65830a89000123456789012341a5108100820083009100" +
	"9200950096009700a658060667810f010201060667810f010203060667810f01" +
	"0204060667810f010205060667810f010207060667810f010208060667810f01" +
	"0209060667810f01020a060667810f01020b060667810f01020d060667810f01" +
	"020eb0820307a0058000810104810667810f010201a20ca10a8b032f0601c603" +
	"010a0ba31ca11a8202412183022f058b032f0604800106a508c00140c103656e" +
	"ffa423a1158202412183022fe28b032f0603880110a503c00140830a98001032" +
	"547698103214a56ba11782044221002183022f008b032f0602800184a503c001" +
	"40831661144f0ca0000000871002ff49ff058950045553494d82010b83166114" +
	"4f0ca0000000871004ff49ff058950044953494d82010b831a61184f10a00000" +
	"03431002f310ffff89020000ff50044353494da6820216a11b82044221002e83" +
	"022f068b032f0602800202b2880130a503c00140831680015ea40683010a9501" +
	"088401d4a40683010a950108820118831b800101900080015aa40683010a9501" +
	"088401d4a40683010a95010882011383108001019000800118a40683010a9501" +
	"0882011e83268001019000800102a4068301019501088401d4a40683010a9501" +
	"08800158a40683010a950108820108832c800103a406830101950108800118a4" +
	"06830181950108800140a40683010a9501088401d4a40683010a950108820102" +
	"832c800101a406830101950108800102a406830181950108800158a40683010a" +
	"9501088401d4a40683010a9501088201028321800103a4068301019501088001" +
	"58a40683010a9501088401d4a40683010a95010882010d8321800101a4068301" +
	"0195010880015aa40683010a9501088401d4a40683010a95010882010d831680" +
	"0101a406830101950108800152a40683010a9501088201188321800101a40683" +
	"010195010880015aa40683010a9501088401d4a40683010a95010882010d8321" +
	"800103a4068301019501088401d4a40683010a950108800158a40683010a9501" +
	"0882010d8316800101a406830101950108800102a40683010a95010882011883" +
	"2c800101a406830101950108800102a4068301819501088401d4a40683010a95" +
	"0108800158a40683010a950108820102831b8001039000800158a40683010a95" +
	"01088401d4a40683010a950108a71ea1158202412183022f088b032f06028801" +
	"40a503c0014083053c3c000000a328a0058000810105a11f300d800101810831" +
	"31313131313131300e8002008181083232323232323232a24ca0058000810102" +
	"a143a0413013800101810830303030ffffffff820101830106301480010a8108" +
	"3535353535353535830103840200aa301480010b810836363636363636368301" +
	"03840200aab2820213a0058000810107810667810f010203a211a10f83027f10" +
	"8b032f0601c60481010a0ba31fa11a82044221001483026f068b032f06028001" +
	"148801b8a503c001408301ffa519a1178202412183026f548b032f0601800112" +
	"a505c1038500ffa831a11782044221001683026fe58b032f0607800116a503c0" +
	"01408316801474656c3a2b313132323333343435353636373738a911a10f8302" +
	"5f508b032f0601c60481010a0baa1da11b82044221000a83024f208b032f060a" +
	"80010aa507c00140c10200ffad1ba1168202412183024f018b032f060a800202" +
	"00a503c001408301ffaf11a10f83025f3a8b032f0601c60481010a0bb063a161" +
	"82044221006483024f308b032f0608800164a54dc14ba823c0034f3a0ac1034f" +
	"1505c5034f0901c6034f4c0bca034f5109c3034f1904c9034f1606a90fc4034f" +
	"1102c4034f1307ca034f1408aa12c2034f1203cb034f3d0cc7024f4bc8024f4d" +
	"ffb41aa1188202412183024f228b032f0607880168a506c00140c20100b51aa1" +
	"188202412183024f238b032f0607880170a506c001c0c20100b61ba115820241" +
	"2183024f248b032f0607880178a503c001c083020002bf2411a10f83025f3c8b" +
	"032f0601c60481010a0bbf2523a1218202412183024f208b032f060a800112a5" +
	"0fc00140c10a000901000101010001ffbf2629a1278202412183024f218b032f" +
	"060a800112a515c00140c110000f0100010101030708020c003e00ffa222a005" +
	"8000810103a119a017301580020081810839393939ffffffff82020081830103" +
	"a18203f6a0058000810117a18203eb308203e78000621a82044221007c83022f" +
	"fb8b032f060e800204d88800a503c0014080027f10621682044621001a83026f" +
	"448b032f06078001828800a50080047f105f3a621a82044221000283024f098b" +
	"032f0607800114880108a503c20100621782044221001183024f118b032f0607" +
	"8001aa880110a500621e82044221000d83024f128b032f0607800182880118a5" +
	"07c00140c10200ff621a82044221001183024f138b032f06078001aa880138a5" +
	"03c00140621882044221002883024f148b032f060780020190880140a500621a" +
	"82044221000383024f158b032f060780011e880128a503c00140621a82044221" +
	"000283024f168b032f0607800114880130a503c0014081020001810200028102" +
	"000081020000810200008102000081020000810200008102000081020000621a" +
	"82044221001483024f198b032f06078001c8880120a503c00140621882044221" +
	"001c83024f3a8b032f060780020118880150a5008131546573746e722e31ffff" +
	"ffffffff069194982143f1ffffffffffffff546573746e722e32ffffffffffff" +
	"069194982143f2621a82044221000f83024f3d8b032f0607800196880160a503" +
	"c00140621982044221000a83024f4b8b032f06078001648800a503c00140621d" +
	"82044221000a83024f4c8b032f0607800164880158a506c00140c20100621982" +
	"044221001483024f4d8b032f06078001c88800a503c00140621b820442210028" +
	"83024f518b032f060780020190880148a503c0014080027f1062138202782183" +
	"025f3e8b032f0601c60481010a0b80047f105f3e62158202412183024f018b03" +
	"2f060a800102a503c001408102070062168202792183024f028b032f060a8002" +
	"0400a503c0014062178202412183024f038b032f060a8001648800a503c00140" +
	"62178202412183024f048b032f060a8001648800a503c0014080006212820278" +
	"2183027f668b032f0601c60481010a0b80027f6662128202782183025f408b03" +
	"2f0601c60481010a0b80047f665f4062178202412183024f408b036f06028001" +
	"018800a503c0014081010062178202412183024f418b036f06028001208800a5" +
	"03c00140812006013c1e3c1e0000000000000000000000000000000000000000" +
	"00000000000000000000621a8202412183024f428b036f06028001068800a506" +
	"c00140c20100621a8202412183024f438b036f06048001208800a506c00140c2" +
	"010062178202412183024f448b036f06048001018800a503c001408101008000" +
	"62128202782183027f268b036f0601c60481010a0b80027f2662468202412183" +
	"026fab8b036f06028001648800a532c00140c12da02a80046781120381030700" +
	"00a21d301b800467811203811353414950322e3311424552544c561153554349" +
	"ffb38204b1a0058000810108810667810f010204a21fa11d83027fd0840ca000" +
	"0000871002ff49ff05898b032f0601c60481010a0ba31ca10f8202412183026f" +
	"078b036f060aa5008309080910101032547698a4820209a11582044221003683" +
	"026f068b036f06088002032aa5008321800101a406830101950108800102a406" +
	"830181950108800158a40683010a9501088201158316800103a4068301019501" +
	"08800158a40683010a9501088201208316800101a40683010195010880015aa4" +
	"0683010a9501088201208321800101a40683010195010880015aa40683010a95" +
	"01088401d4a40683010a95010882011583268001019000800102a40683010195" +
	"01088401d4a40683010a950108800158a40683010a9501088201108321800103" +
	"a4068301019501088401d4a40683010a950108800158a40683010a9501088201" +
	"158310800101900080015aa40683010a950108820126831b800101900080015a" +
	"a40683010a9501088401d4a40683010a95010882011b832c800101a406830101" +
	"950108800102a4068301819501088401d4a40683010a950108800158a4068301" +
	"0a95010882010a8316800101a40683010195010880011aa40683010a95010882" +
	"01208336800101a406830101950108800158a40683010a950108840132a40683" +
	"0101950108800102a010a406830101950108a406830181950108820100830b80" +
	"0103a40683010a95010882012b831680015ea40683010a9501088401d4a40683" +
	"010a950108820120831b80010390008401d4a40683010a950108800158a40683" +
	"010a95010882011b831680015fa40683010a9501088401d4a40683010a950108" +
	"a518a1168202412183026f088b036f0602a507c00180c10207ffa618a1168202" +
	"412183026f098b036f0602a507c00180c10207ffa714a10f8202412183026f31" +
	"8b036f0603a500830100a827a1128202412183026f388b036f0604800111a500" +
	"83119effbf1dff3e0083410310010400403e39a916a11482044221001c83026f" +
	"3b8b036f060180018ca500aa1ba1198204422100b083026f3c8b036f06028002" +
	"06e0a504c10200ffab16a11482044221002a83026f428b036f0602800154a500" +
	"ac11a10f8202412183026f438b036f0602a500ad1ea11c8202412183026f468b" +
	"036f0607a50dc10b0147534d411154455354ffae14a10f8202412183026f568b" +
	"036f0601a500830100af1ca1128202412183026f5b8b036f0602a503c0018083" +
	"06f00000f00000b014a1128202412183026f5c8b036f0603a503c201ffb124a1" +
	"128202412183026f738b036f0602a503c00180830effffffffffffff42f618ff" +
	"feff01b215a10f8202412183026f788b036f0603a50083020001b311a10f8202" +
	"412183026f7b8b036f0606a500b421a1128202412183026f7e8b036f0602a503" +
	"c00180830bffffffff42f618fffeff01b517a10f8202412183026fad8b036f06" +
	"07a500830480000002b636a11482044221000e83026fb78b036f060880011ca5" +
	"00830e11f2ff4575726f20456d6572ff00830e19f1ff456d657267656e6379ff" +
	"00b717a1158202412183026fc48b036f0602800132a503c00180b81fa1128202" +
	"412183026fe38b036f0602a503c001c082010c8306000000000001b919a11782" +
	"044221003683026fe48b036f0602800136a503c001c0b48209dda00580008101" +
	"09810667810f010205a211a10f8202412183026f058b036f0605a500a317a115" +
	"8202412183026f378b036f0609a506c00140c20100a41fa11d82044621000383" +
	"026f398b036f060b80010f8801e0a506c00180c20100a518a112820241218302" +
	"6f3e8b036f0604800102a5008302ffffa618a1128202412183026f3f8b036f06" +
	"04800102a5008302ffffa716a11482044221002783026f408b036f060480014e" +
	"a500a818a10f8202412183026f418b036f0601a5008305ffffff0000a914a112" +
	"8202412183026f458b036f0602800108a500aa14a1128202412183026f488b03" +
	"6f0604800108a500ab16a11482044221001c83026f498b036f060a80018ca500" +
	"ac1aa11882044221000d83026f4b8b036f0601800141a504c10200ffad1aa118" +
	"82044221000d83026f4c8b036f0603800141a504c10200ffae14a11282024121" +
	"83026f508b036f0606800110a500af81c1a1128202412183026f608b036f0606" +
	"8001aaa5008381aaffffff0000ffffff0000ffffff0000ffffff0000ffffff00" +
	"00ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ff" +
	"ffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff" +
	"0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000" +
	"ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000b082" +
	"0111a1128202412183026f618b036f06038001faa5008381faffffff0000ffff" +
	"ff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff00" +
	"00ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ff" +
	"ffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff" +
	"0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000" +
	"ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffff" +
	"ff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff00" +
	"00ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ff" +
	"ffff0000ffffff0000ffffff0000ffffff0000b1820111a1128202412183026f" +
	"628b036f06038001faa5008381faffffff0000ffffff0000ffffff0000ffffff" +
	"0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000" +
	"ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffff" +
	"ff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff00" +
	"00ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ff" +
	"ffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff" +
	"0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000" +
	"ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffff" +
	"ff0000ffffff0000ffffff0000ffffff0000b214a1128202412183026f2c8b03" +
	"6f0602a503c00140b317a1158202412183026f328b036f060380013ca503c001" +
	"40b41ba11982044221001e83026f478b036f06028002012ca504c10200ffb519" +
	"a11782044221001583026f4d8b036f060180013fa503c00140b61aa118820442" +
	"21000d83026f4e8b036f0602800141a504c10200ffb713a11182044221000f83" +
	"026f4f8b036f0602a500b918a1168202412183026f578b036f06018001c8a504" +
	"c10200ffba19a11782044221005583026f588b036f06038001aaa503c00140bb" +
	"44a14282044621002a83026f808b036f06028001d2a52ec00180c129ffffffff" +
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
	"ffffffffffffff0000000000ffbc43a14182044621002983026f818b036f0602" +
	"8001cda52dc00180c128ffffffffffffffffffffffffffffffffffffffffffff" +
	"ffffffffffffffffffffffffffffff00000000ffbd1ca11a8204462100038302" +
	"6f828b036f060b80011ea506c00180c20100be1ca11a82044621000383026f83" +
	"8b036f060b80011ea506c00180c20100bf1f81e2a1158202412183026fb18b03" +
	"6f06048001c8a503c001408381c821ffffff21f3ffff2143ffff2143f8ff2143" +
	"19ff215320f92153f1ff2153f2ff2153f3ff2153f4ff2153f5ff2153f6ff2153" +
	"f7ff2153f8ff2153f9ff0200f0ff0200f1ff0200f2ff0200f3ff0200f4ff0200" +
	"f5ff0200f6ff0200f7ff0200f8ff0200f9ff0210f0ff6666f0ff6666f1ff6666" +
	"f2ff666683ff6666f4ff6666f5ff6666f6ff6666f7ff6666f8ff6666f9ff6676" +
	"f0ff0821f0ff0821f1ff0821f2ff0821f3ff0821f4ff0821f5ff0821f6ff0821" +
	"f7ff0821f8ff0821f9ff0831f0ff9999f9ff111111f9bf201da1128202412183" +
	"026fb28b036f0603a503c001408307150000000000fcbf2181e2a11582024121" +
	"83026fb38b036f06048001c8a503c001408381c821ffffff21f3ffff2143ffff" +
	"2143f8ff214319ff215320f92153f1ff2153f2ff2153f3ff2153f4ff2153f5ff" +
	"2153f6ff2153f7ff2153f8ff2153f9ff0200f0ff0200f1ff0200f2ff0200f3ff" +
	"0200f4ff0200f5ff0200f6ff0200f7ff0200f8ff0200f9ff0210f0ff6666f0ff" +
	"6666f1ff6666f2ff666683ff6666f4ff6666f5ff6666f6ff6666f7ff6666f8ff" +
	"6666f9ff6676f0ff0821f0ff0821f1ff0821f2ff0821f3ff0821f4ff0821f5ff" +
	"0821f6ff0821f7ff0821f8ff0821f9ff0831f0ff9999f9ff111111f9bf221da1" +
	"128202412183026fb48b036f0603a503c001408307150000000000fcbf2317a1" +
	"158202412183026fb58b036f0603a506c00140c20100bf2417a1128202412183" +
	"026fb68b036f0602a503c00140830100bf2511a10f8202412183026fc38b036f" +
	"0602a500bf2619a11482044221001483026fc58b036f0608800164a5008301ff" +
	"bf2719a11482044221000883026fc68b036f0608800150a5008301ffbf2f1ca1" +
	"1a82044221000583026fce8b036f0606800105a506c104000000ffbf3017a115" +
	"82044221000d83026fcf8b036f0606a504c10200ffbf3114a112820241218302" +
	"6fd08b036f0604800117a500bf3216a11482044221000a83026fd18b036f0606" +
	"80010aa500bf3314a1128202412183026fd28b036f0609800117a500bf3419a1" +
	"1782044221002083026fd38b036f060a8001a0a503c00140bf351ba115820241" +
	"2183026fd48b036f0604800102a503c0014083020103bf361ba1158202412183" +
	"026fd58b036f0604800102a503c0014083020103bf3a17a1158202412183026f" +
	"d98b036f060380011ea503c00140bf3c17a1128202412183026fdb8b036f0603" +
	"a503c00140830100bf3d17a1128202412183026fdc8b036f0603a503c0014083" +
	"0100bf431aa1158202412183026fe88b036f060480011ca503c001408301ffbf" +
	"4619a11782044221001483026fed8b036f0601800128a503c00140bf4819a117" +
	"82044221001483026fef8b036f0603800128a503c00140a222a005800081010a" +
	"a119a017301580020081810839393939ffffffff82020081830103a435a00580" +
	"0081010ba12ca12a8001038101028210000102030405060708090a0b0c0d0e0f" +
	"831000000000000000000000000000000000a182014ea0058000810118a18201" +
	"433082013f80027fd062138202782183025f508b036f060dc60481010a0b8004" +
	"7fd05f50621582044221003b83024f818b036f060680020127a5006215820442" +
	"21006483024f828b036f06068002012ca500621582044221006483024f838b03" +
	"6f06068002012ca500621782044221001483024f848b036f0604800114a503c0" +
	"0140621782044221001483024f858b036f0604800114a503c001406217820442" +
	"21000383024f868b036f0604800103a503c0014080027fd06213820278218302" +
	"7f668b036f060dc60481010a0b80047fd07f6662138202782183025f408b036f" +
	"060dc60481010a0b80047fd05fc062188202792183024f0b8b036f0604800204" +
	"008800a503c0014080027fd062188202792183026ffe8b036f06048002040088" +
	"00a503c0014080027fb062188202792183026ffe8b036f0604800204008800a5" +
	"03c00140a18201ada0058000810119a18201a23082019e80027f106219820442" +
	"21001c83026f3a8b032f06058800c7067f105f3a4f3a621782044221001c8302" +
	"6f3b8b032f060d8800c7047fd06f3b62178204422100b083026f3c8b032f060b" +
	"8800c7047fd06f3c621782044221002783026f408b032f0608800c7047fd06f40" +
	"621782044221002a83026f428b032f06078800c7047fd06f4262158202412183" +
	"026f438b032f060b8800c7047fd06f43621782044221001e83026f478b032f06" +
	"078800c7047fd06f47621782044221001c83026f498b032f06088800c7047fd0" +
	"6f49621982044221000d83026f4a8b032f06078800c7067f105f3a4f12621782" +
	"044221000d83026f4b8b032f06068800c7047fd06f4b621782044221000d8302" +
	"6f4c8b032f06088800c7047fd06f4c80067fd07f665f4062178202412183024f" +
	"408b036f06088800c7067f665f404f4062178202412183024f418b036f060888" +
	"00c7067f665f404f4162178202412183024f428b036f06088800c7067f665f40" +
	"4f4262178202412183024f438b036f060e8800c7067f665f404f436217820241" +
	"2183024f448b036f060e8800c7067f665f404f44a6820165a005800081011aa1" +
	"484f07a00000015153504f08a0000001515350414f08a0000001510000008203" +
	"82dc0083010fc90d810280008201f08301f08701f0ea12801001000000000201" +
	"0206b2010000000000a281d83022950118820101830101301730158001808610" +
	"000102030405060708090a0b0c0d0e0f30229501148201028301013017301580" +
	"01808610000102030405060708090a0b0c0d0e0f3022950114882010383010130" +
	"1730158001808610000102030405060708090a0b0c0d0e0f3022950118820101" +
	"830102301730158001888610000102030405060708090a0b0c0d0e0f30229501" +
	"14820102830102301730158001888610000102030405060708090a0b0c0d0e0f" +
	"3022950148820103830102301730158001888610000102030405060708090a0b" +
	"0c0d0e0fa33704350070326630732e06072a864886fc6b01600b06092a864886" +
	"fc6b020202630906072a864886fc6b03640b06092a864886fc6b048000a722a0" +
	"05800081011b4f09a00000055910100001a0050403b001208101020401000401" +
	"00a738a005800081011c4f09a00000055910100002a0050403b0014081010204" +
	"01000401003014800ca0000000871002ff49ff0589810100820100a738a00580" +
	"0081011d4f09a00000055910100003a0050403b0014181010204010004010030" +
	"14800ca0000000871004ff49ff0589810100820100a73ca005800081011e4f09" +
	"a00000055910100004a0050403b0014281010204010004010030188010a00000" +
	"03431002f310ffff89020000ff810100820100aa07a005800081011f"

