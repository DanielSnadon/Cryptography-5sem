using CryptoLab3;

// _ _ _ Punkt 1 _ _ _

// Обычный функционал:

var service = new HelperFuncs();

Console.WriteLine($"Сложение: 0x{service.Add(0x0B, 0x0D):X2}");
Console.WriteLine($"Умножение: 0x{service.Multiply(0x83, 0x03, 0x1B):X2}");

var moduli = service.GetIreducibles();
Console.WriteLine($"Количество неприводимых модулей: {moduli.Count}");

byte inverse = service.Inverse(0x02, 0x1B);

Console.WriteLine($"Обратный к 0x02: 0x{inverse:X2}");
Console.WriteLine($"Произведение: 0x{service.Multiply(0x02, inverse, 0x1B):X2}");

var factors = service.Factorize(0b11011);
Console.WriteLine($"Множители: {string.Join(", ", factors)}");

// Исключения:

try
{
    service.Inverse(0x00, 0x1B);
    throw new InvalidOperationException("Inverse принимает нулевой элемент.");
}
catch (ArgumentException exception)
{
    Console.WriteLine($"Inverse отклоняет нулевой элемент. {exception}");
}

try
{
    service.Inverse(0x02, 0x01);
    throw new InvalidOperationException("Inverse принимает приводимый модуль.");
}
catch (ArgumentException exception)
{
    Console.WriteLine($"Inverse отклоняет приводимый модуль. {exception}");
}

try
{
    service.Multiply(0x02, 0x03, 0x01);
    throw new InvalidOperationException("Multiply принимает приводимый модуль.");
}
catch (ArgumentException exception)
{
    Console.WriteLine($"Multiply отклоняет приводимый модуль. {exception}");
}
