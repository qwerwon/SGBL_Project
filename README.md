# Transaction Part
<img src="https://user-images.githubusercontent.com/38277490/44906451-e2916080-ad4f-11e8-809a-f963283f8b9c.png" width = "65%">

# Block Part
<img src="https://user-images.githubusercontent.com/38277490/44907091-d4dcda80-ad51-11e8-8a90-001dd719986d.png" width = "65%">
<img src="https://user-images.githubusercontent.com/38277490/44907163-00f85b80-ad52-11e8-9984-64702b0c73cc.png" width = "65%">



오늘 해야하는 일!!

1. Msg handling
2. block, transaction isValid()
3. Fork choice
4. Re-organization
(5. transaction priority(in block))


6. 채점


def mining(): + block 생성 시
모든 tx_set에 대해서 utxo_set 추가/제거(현재는 coinbase transaction에 대해서만 추가함)


기존에는 transaction이 생성되면, UTXOset을 update
오늘, block 생성 시에 utxo set을 update하는 부분을 구현해야 함


def generate_transaction(receiver, amount, commission):
서명부분
utxo set에 넣고 빼는거 삭제


def get_candidateblock():
memory pool에서 transaction 가져오는거
commission 계산하는거


transaction isValid()
1. 타입 및 format 체크
2. 입력값과 출력값이 비어있지 않다(입력이 비어있다면, coinbase가 맞는지 확인하고 100개의 block interval이 지나야함).
4. 해당 input의 unlock(서명)이 대응하는 publickey를 이용해서 복호화 가능한지 확인
5. input의 총합이 output의 총합보다 크거나 같아야함
6. input이 이미 사용된 input인지 memorypool에서 확인한다

block isValid( )
1. hash값이 일치하는지
2. 난이도 계산법이 맞는지(get_difficulty 호출)
3. hash가 targetvalue보다 작은지
4. 2시간 이내에 만들어졌는지
5. 첫번째 거래가 coinbase transaction인지
6. 모든 transaction에 대해서 isValid check
7. transaction 개수가 최대치를 넘었는지


block을 전파받았을 때 시나리오
isValid 검증, 유효하면 전파
(mining 중이면)
현재 작업중인 candidate block을 파기하고 새로운 candidate block 생성
memory pool/UTXOset 업데이트

transaction을 전파받았을 때 시나리오
isValid 검증, 유효하면 전파
memorypool 업데이트
