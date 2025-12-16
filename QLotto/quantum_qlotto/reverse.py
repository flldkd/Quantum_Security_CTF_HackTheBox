
def solve_qlotto(testing_numbers):
    """
    根据 Testing Numbers 计算 Lotto Numbers。
    原理：Lotto bits = ~Testing bits (按位取反)
    推导公式：Lotto = ((21 - (Test - 1)) % 42) + 1
    """
    lotto_numbers = []
    for t in testing_numbers:
        # 公式推导：
        # Raw_Lotto = 63 - Raw_Test
        # Final_Lotto = (Raw_Lotto % 42) + 1
        # Final_Lotto = ((63 - Raw_Test) % 42) + 1
        #             = ((21 - Raw_Test) % 42) + 1
        # Raw_Test 与 (t-1) 同余 42，所以可以直接替换
        val = ((21 - (t - 1)) % 42) + 1
        lotto_numbers.append(val)
    return lotto_numbers

if __name__ == "__main__":
    print("--- QLotto Solver ---")
    print("请先在服务器输入量子指令: H:0;RXX:90,0,1;H:0;Z:0;H:0")
    
    try:
        user_input = input("请输入服务器返回的 draws 数组 (例如 25,21,10...): ")
        # 处理可能的方括号
        clean_input = user_input.replace('[', '').replace(']', '')
        if not clean_input.strip():
            print("输入为空")
            exit()
            
        testing_nums = [int(x.strip()) for x in clean_input.split(',')]
        
        if len(testing_nums) != 6:
            print(f"警告: 输入了 {len(testing_nums)} 个数字，通常需要 6 个。")

        winning_nums = solve_qlotto(testing_nums)
        
        print("\n[+] 计算出的必胜数字 (复制粘贴回服务器):")
        print(",".join(map(str, winning_nums)))
        
    except ValueError:
        print("[-] 输入格式错误，请确保输入的是逗号分隔的数字。")
