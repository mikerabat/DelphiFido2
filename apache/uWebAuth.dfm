object modWebAuth: TmodWebAuth
  OldCreateOrder = False
  OnCreate = WebModuleCreate
  OnDestroy = WebModuleDestroy
  Actions = <
    item
      Name = 'itEnroll'
      PathInfo = '/enroll'
      OnAction = modWebAuthitEnrollAction
    end
    item
      Name = 'waEnrollVerify'
      PathInfo = '/enrollVerify'
      OnAction = modWebAuthwaEnrollVerifyAction
    end
    item
      Name = 'waSettings'
      PathInfo = '/settings'
      OnAction = modWebAuthwaSettingsAction
    end
    item
      Name = 'waUserExists'
      PathInfo = '/userexists'
      OnAction = modWebAuthwaUserExistsAction
    end
    item
      Name = 'waAssertStart'
      PathInfo = '/assertstart'
      OnAction = modWebAuthwaAssertStartAction
    end
    item
      Name = 'waAssert'
      PathInfo = '/assertverify'
      OnAction = modWebAuthwaAssertAction
    end>
  Height = 150
  Width = 215
end
