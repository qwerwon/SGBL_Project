# Transaction Part
<img src="https://user-images.githubusercontent.com/38277490/44906451-e2916080-ad4f-11e8-809a-f963283f8b9c.png" width = "65%">

# Block Part
<img src="https://user-images.githubusercontent.com/38277490/44907091-d4dcda80-ad51-11e8-8a90-001dd719986d.png" width = "65%">
<img src="https://user-images.githubusercontent.com/38277490/44907163-00f85b80-ad52-11e8-9984-64702b0c73cc.png" width = "65%">



To Do List

1. Msg handling
2. Fork choice
3. Re-organization
4. Grading function

When Block msg arrived:
1. Call isValid
2. Broadcast
3. 현재 작업중인 candidate block을 파기하고 새로운 candidate block 생성
4. memory pool/UTXOset 업데이트

When Transaction msg arrived:
1. Call isValid
2. Broadcast
3. memorypool 업데이트
