from datetime import datetime, timedelta
import random
k = 23 #Change the value of k to observe the duplicates (if any)

def generate_birthdays(group_size):
    jan_first = datetime(2022, 1, 1)
    birthday_list = [(jan_first + timedelta(days=random.randint(0,365)))
                     .strftime("%m/%d/%Y") for i in range(group_size)]
    return sorted(birthday_list)

def shared_bday(group_size):
    duplicate = []
    birthdays = generate_birthdays(group_size)
    print('Generated random birthdays:', birthdays)
    for a, birthdayA in enumerate(birthdays):
        for b, birthdayB in enumerate(birthdays[a + 1 :]):
            if birthdayA == birthdayB:
                duplicate.append(birthdayA)
    return duplicate

duplicate = shared_bday(k)
print('The duplicate birthday(s):', duplicate)