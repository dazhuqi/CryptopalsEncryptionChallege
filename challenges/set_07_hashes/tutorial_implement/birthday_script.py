try:
    from . import birthdaya, birthdayc, birthdaye
except ImportError:
    import birthdaya
    import birthdayc
    import birthdaye

K_VALUES = [5, 10, 15, 20, 23, 30, 40, 50]
TRIALS = 1000

def run_part_a():
    print("=" * 60)
    print("PART A - Duplicate Birthday Observation")
    print("=" * 60)

    for k in K_VALUES:

        print(f"\nGroup Size k = {k}")

        for trial in range(3):
            duplicate = birthdaya.shared_bday(k)
            print(f"Trial {trial + 1}: {duplicate if duplicate else 'No duplicate'}")


def run_part_c():
    print("\n")
    print("=" * 60)
    print("PART C - Birthday Paradox Probability")
    print("=" * 60)

    print(f"{'k':<10}{'Probability':<15}")

    for k in K_VALUES:

        probability = birthdayc.generate_trials(k,TRIALS)

        print(f"{k:<10}{probability:<15.4f}")


def run_part_e():
    print("\n")
    print("=" * 60)
    print("PART E - Specific Birthday Collision")
    print("=" * 60)

    special_k_values = [50, 100, 150, 200, 253, 300]

    print(f"{'k':<10}{'Probability':<15}")

    for k in special_k_values:

        probability = birthdaye.generate_trials(k, TRIALS)

        print(f"{k:<10} {probability:<15.4f}")


if __name__ == "__main__":

    run_part_a()
    run_part_c()
    run_part_e()
