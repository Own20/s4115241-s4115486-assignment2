def is_prime(num):
    # Check if the number is less than or equal to 1
    if num <= 1:
        return False
    # 2 and 3 are prime numbers
    if num == 2 or num == 3:
        return True
    # Exclude even numbers and multiples of 3
    if num % 2 == 0 or num % 3 == 0:
        return False
    # Check from 5 to the square root of the number
    i = 5
    print(i)
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

print(is_prime(11))