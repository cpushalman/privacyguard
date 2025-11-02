import time
import cv2 as cv
import mediapipe as mp


class handDetctor():
    def __init__(self, mode=False, maxHands=2, detectionCon=0.5, trackCon=0.5):
        self.mode = mode
        self.maxHands = maxHands
        self.detectionCon = detectionCon
        self.trackCon = trackCon
        self.mpHands = mp.solutions.hands
        self.hands = self.mpHands.Hands(
            static_image_mode=self.mode,
            max_num_hands=self.maxHands,
            min_detection_confidence=self.detectionCon,
            min_tracking_confidence=self.trackCon
        )
        self.mpDraw = mp.solutions.drawing_utils


    def findHands(self,frame,draw=True):
        imgRGB = cv.cvtColor(frame, cv.COLOR_BGR2RGB)
        self.results = self.hands.process(imgRGB)
        if self.results.multi_hand_landmarks:
            for handLms in self.results.multi_hand_landmarks:
                if draw:
                    self.mpDraw.draw_landmarks(frame, handLms,self.mpHands.HAND_CONNECTIONS)

        return frame

    def findPosition(self,frame,handNo=0,draw=True):
        lmlist = []
        if self.results.multi_hand_landmarks:
            myHand= self.results.multi_hand_landmarks[handNo]
            for id, lm in enumerate(myHand.landmark):
                h, w, c = frame.shape
                cx, cy = int(lm.x * w), int(lm.y * h)
                #print(id, cx, cy)
                lmlist.append([id, cx, cy])
                if draw:
                    cv.circle(frame, (cx, cy), 5, (255, 0, 255), cv.FILLED)

        return lmlist







def main():
    cTime = 0
    pTime = 0
    capture = cv.VideoCapture(0)
    detector = handDetctor()
    if not capture.isOpened():
        print("❌ Camera failed to open")
        exit()

    while True:
        isTrue, frame = capture.read()
        frame= detector.findHands(frame)
        lmlist = detector.findPosition(frame)
        if len(lmlist) != 0:
            print(lmlist[4])
        cTime = time.time()
        fps = 1 / (cTime - pTime)
        pTime = cTime

        cv.putText(frame, str(int(fps)), (10, 70), cv.FONT_HERSHEY_SIMPLEX, 3, (255, 0, 255), 3)
        if not isTrue:
            print("❌ Failed to read frame")
            break

        cv.imshow('Video', frame)

        if cv.waitKey(20) & 0xFF == ord('d'):
            break

    capture.release()
    cv.destroyAllWindows()


if __name__ == "__main__":
    main()
