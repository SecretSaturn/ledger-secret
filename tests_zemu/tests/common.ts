/** ******************************************************************************
 *  (c) 2021-2023 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */
import { DEFAULT_START_OPTIONS, IDeviceModel } from '@zondax/zemu'

const Resolve = require('path').resolve

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')
const APP_PATH_SP = Resolve('../app/output/app_s2.elf')
const APP_PATH_ST = Resolve('../app/output/app_stax.elf')

export const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

export const DEVICE_MODELS: IDeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
]

export const example_tx_str_basic = {
  account_number: '108',
  chain_id: 'secret-4',
  fee: {
    amount: [
      {
        amount: '600',
        denom: 'uscrt',
      },
    ],
    gas: '200000',
  },
  memo: '',
  msgs: [
    {
      type: 'cosmos-sdk/MsgWithdrawDelegationReward',
      value: {
        delegator_address: 'secret1w34k53py5v5xyluazqpq65agyajavep2rflq6h',
        validator_address: 'secretvaloper1kn3wugetjuy4zetlq6wadchfhvu3x740ae6z6x',
      },
    },
    {
      type: 'cosmos-sdk/MsgWithdrawDelegationReward',
      value: {
        delegator_address: 'secret1w34k53py5v5xyluazqpq65agyajavep2rflq6h',
        validator_address: 'secretvaloper1sjllsnramtg3ewxqwwrwjxfgc4n4ef9u2lcnj0',
      },
    },
  ],
  sequence: '106',
}

export const example_tx_str_expert = {
  account_number: '108',
  chain_id: 'secret-4',
  fee: {
    amount: [
      {
        amount: '600',
        denom: 'uscrt',
      },
    ],
    gas: '200000',
  },
  memo: '',
  msgs: [
    {
      type: 'cosmos-sdk/MsgWithdrawDelegationReward',
      value: {
        delegator_address: 'secret1kky4yzth6gdrm8ga5zlfwhav33yr7hl87jycah',
        validator_address: 'secretvaloper1kn3wugetjuy4zetlq6wadchfhvu3x740ae6z6x',
      },
    },
    {
      type: 'cosmos-sdk/MsgWithdrawDelegationReward',
      value: {
        delegator_address: 'secret1kky4yzth6gdrm8ga5zlfwhav33yr7hl87jycah',
        validator_address: 'secretvaloper1sjllsnramtg3ewxqwwrwjxfgc4n4ef9u2lcnj0',
      },
    },
  ],
  sequence: '106',
}

export const example_tx_str_combined = {
  account_number: '108',
  chain_id: 'secret-4',
  fee: {
    amount: [
      {
        amount: '600',
        denom: 'uscrt',
      },
    ],
    gas: '200000',
  },
  memo: '',
  msgs: [
    {
      type: 'cosmos-sdk/MsgWithdrawDelegationReward',
      value: {
        delegator_address: 'secret1w34k53py5v5xyluazqpq65agyajavep2rflq6h',
        validator_address: 'secretvaloper1648ynlpdw7fqa2axt0w2yp3fk542junl7rsvq6',
      },
    },
    {
      type: 'cosmos-sdk/MsgDelegate',
      value: {
        amount: {
          amount: '20139397',
          denom: 'uscrt',
        },
        delegator_address: 'secret1w34k53py5v5xyluazqpq65agyajavep2rflq6h',
        validator_address: 'secretvaloper1648ynlpdw7fqa2axt0w2yp3fk542junl7rsvq6',
      },
    },
  ],
  sequence: '106',
}

export const example_tx_str_basic2 = {
  account_number: '482',
  chain_id: 'secret-4',
  fee: {
    amount: [],
    gas: '10000000',
  },
  memo: '',
  msgs: [
    {
      type: 'somechain/MsgNew',
      value: {
        coins: [
          {
            amount: '20139397',
            asset: 'uscrt',
          },
        ],
        memo: 'memo_text_goes_here',
        signer: 'secret1w34k53py5v5xyluazqpq65agyajavep2rflq6h',
      },
    },
  ],
  sequence: '6',
}

export const example_tx_str_basic_extra_fields = {
  account_number: '108',
  chain_id: 'secret-4',
  extra_field: 'empty',
  fee: {
    amount: [
      {
        amount: '600',
        denom: 'uscrt',
      },
    ],
    gas: '200000',
  },
  foo: 'bar',
  memo: '',
  msgs: [
    {
      type: 'cosmos-sdk/MsgWithdrawDelegationReward',
      value: {
        delegator_address: 'secret1w34k53py5v5xyluazqpq65agyajavep2rflq6h',
        validator_address: 'secretvaloper1kn3wugetjuy4zetlq6wadchfhvu3x740ae6z6x',
      },
    },
    {
      type: 'cosmos-sdk/MsgWithdrawDelegationReward',
      value: {
        delegator_address: 'secret1w34k53py5v5xyluazqpq65agyajavep2rflq6h',
        validator_address: 'secretvaloper1sjllsnramtg3ewxqwwrwjxfgc4n4ef9u2lcnj0',
      },
    },
  ],
  sequence: '106',
  unknown_field: 123456
}

export const ibc_denoms = {
  account_number: "0",
  chain_id: "secret-4",
  fee: {
    amount: [
      {
        "amount": '5',
        "denom": 'uscrt',
      }
    ],
    gas: '10000',
  },
  memo: "testmemo",
  msgs: [
    {
      inputs: [
        {
          address: "secretaccaddr1d9h8qat5e4ehc5",
          coins: [
            {
              amount: '10',
              denom: 'ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2'
            }
          ]
        }
      ],
      outputs: [
        {
          address: 'secretaccaddr1da6hgur4wse3jx32',
          coins: [
            {
              amount: '10',
              denom: 'ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2'
            }
          ]
        }
      ]
    }
  ],
  sequence: '1'
}

export const votingOptions = {
  account_number: "0",
    chain_id: "secret-4",
    fee: {
      amount: [
        {
          amount: "50000",
          denom: "uscrt"
        }
      ],
      gas: "10000"
    },
    memo: "",
    msgs: [
      {
        type: "cosmos-sdk/MsgVote",
        value: {
          option: "2",
          proposal_id: "113",
          voter:"secret1q0rth4fu4svxnw63vjd7w74nadzsdp0f23e0uy"
        }
      }
    ],
    sequence: "1"
}
