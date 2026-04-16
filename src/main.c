#include "keyboard_protector.h"

int main(void) {
    KeyProtectorStatus initStatus = SetHook();
    KeyProtectorStatus exitStatus = initStatus;
    MSG msg = {0};

    if (IsFatalStatus(initStatus)) {
        fprintf(stderr, "[error] Initialization failed: %s\n", KeyProtectorStatusToString(initStatus));
        return (int)initStatus;
    }

    for (;;) {
        BOOL messageResult = GetMessage(&msg, NULL, 0, 0);
        if (messageResult == -1) {
            fprintf(stderr, "[error] Message loop failed.\n");
            exitStatus = KEYPROTECTOR_STATUS_MESSAGE_LOOP_FAILED;
            break;
        }

        if (messageResult == 0) {
            break;
        }

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (exitStatus != KEYPROTECTOR_STATUS_MESSAGE_LOOP_FAILED) {
        exitStatus = GetRuntimeStatus();
    }

    UnsetHook();
    printf("[shutdown] Keyboard protector exited with status: %s\n", KeyProtectorStatusToString(exitStatus));
    return (int)exitStatus;
}
