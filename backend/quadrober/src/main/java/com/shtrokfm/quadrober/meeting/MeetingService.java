package com.shtrokfm.quadrober.meeting;

import com.shtrokfm.quadrober.entity.Meeting;
import com.shtrokfm.quadrober.model.CreateMeetingResponse;
import com.shtrokfm.quadrober.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.time.ZoneId;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MeetingService {
  private final MeetingRepository meetingRepository;
  private final UserRepository userRepository;

  /**
   * Создает новую встречу, если нет встреч поблизости в этот день
   * Иначе отправляет список встреч
   * @param meeting
   * @return
   */
  public CreateMeetingResponse create(Meeting meeting) {
    List<Meeting> nearMeetings = this.findNearMeetings(
      meeting.getAddress().getPoint(),
      meeting.getMeetingDateTime(),
      1000.0
    );

    Optional<Meeting> newMeeting = Optional.empty();

    if (nearMeetings.isEmpty()) {
      newMeeting = Optional.of(this.meetingRepository.save(meeting));
    }

    // { id: 'string',  nearMeetings: Meeting[] }
    // Если список пустой, значит создали встречу
    return new CreateMeetingResponse(newMeeting.map(Meeting::getId).orElse(null), nearMeetings);
  }

  private List<Meeting> findNearMeetings(
    double[] pointCoordinates,
    Instant meetingDateTime,
    double radiusInMeters
  ) {

    if (meetingDateTime == null) {
      return this.meetingRepository.findNearMeetings(
        pointCoordinates[0],
        pointCoordinates[1],
        radiusInMeters
      );
    }


    // Устанавливаем начало и конец встречи;
    Instant startOfDay = meetingDateTime.atZone(ZoneId.of("UTC")).toLocalDate().atStartOfDay(ZoneId.of("UTC")).toInstant().plus(Duration.ofMinutes(180)); // Начало дня в UTC
    Instant endOfDay = startOfDay.plusSeconds(86400).plus(Duration.ofMinutes(180)); // Конец дня (86400 секунд = 1 день)

    return this.meetingRepository.findByLocationNearInCurrentDay(
      pointCoordinates[0],
      pointCoordinates[1],
      radiusInMeters,
      startOfDay,
      endOfDay
    );
  }

  public Boolean delete(String meetingId) {
    this.meetingRepository.deleteById(meetingId);

    return true;
  }

  public Meeting update(Meeting meeting) {
    // достаем нашу встречу
    Meeting matchMeeting = this.meetingRepository.findById(meeting.getId()).orElse(null);

    // Если встречи не нашлось, кидаем 404
    if (matchMeeting == null) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Не найдена встреча по данному идентификатору");
    }

    // Проверяем нет ли встреч в этом месте в это время
    List<Meeting> nearMeetings = this.findNearMeetings(
      meeting.getAddress().getPoint(),
      meeting.getMeetingDateTime(),
      1000
    ).stream().filter(nearMeeting ->
      !Objects.equals(meeting.getId(), nearMeeting.getId())).toList();

    if (!nearMeetings.isEmpty()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "В это время в этом месте уже запланирована другая встреча");
    }

    Meeting updatedMeeting = new Meeting(
      meeting.getId(),
      matchMeeting.getOwner(),
      matchMeeting.getFollowers(),
      meeting.getAddress(),
      meeting.getMeetingDateTime()
    );

    // Обновляем встречу
    return this.meetingRepository.save(updatedMeeting);
  }

  public void addFollower(String meetingId, String followerId) {
    // Проверить не участвует ли юзер в других встречах в это время
    // Проверить нет ли у него уже запланированной встречи
  }

  public void deleteFollower(String meetingId, String followerId) {

  }

  /**
   * Получить встречи в которых участвует пользователь
   */
  public List<Meeting> getMyMeetings() {
    // Нужна пагинация
    // Ставить первыми те встречи, в которых участвует пользователь
    // TODO Добавить пользователя из токена
//    User user = this.userRepository.findById().orElse(null);
    return meetingRepository.findByUserId("671cc5a63774c6062f9cb8e6");
  }

  public Meeting getById(String meetingId) {
    Meeting meeting = this.meetingRepository.findById(meetingId).orElse(null);

    if (meeting == null) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }

    return meeting;
  }

  /**
   * // TODO ПОпробовать решить через Criteria И проверить как работает в других таймзонах
   * Получаем ближайшие встречи по координатам
   * Также можно указать дату
   * @param pointCoordinates
   * @param meetingDateTime
   * @return
   */
  public List<Meeting> getNearMeetings(double[] pointCoordinates, Instant meetingDateTime) {
    double radiusInMeters = 5000.0;

    List<Meeting> nearMeetings = this.findNearMeetings(
      pointCoordinates,
      meetingDateTime,
      radiusInMeters
    );

    return nearMeetings;
  }

  public List<Meeting> findNearMeetings(
    double[][] bounds,
    Instant meetingDateTime,
    Integer timezoneOffset
  ) {
    // Верхний левый угол
    double upperLeftLongitude = bounds[0][0]; // Долгота
    double upperLeftLatitude = bounds[0][1];  // Широта

    // Нижний правый угол
    double lowerRightLongitude = bounds[1][0]; // Долгота
    double lowerRightLatitude = bounds[1][1];  // Широта

    if (meetingDateTime == null) {
      return this.meetingRepository.findByLocationWithinBounds(
        upperLeftLongitude,
        lowerRightLatitude,
        lowerRightLongitude,
        upperLeftLatitude
      );
    }

    // Устанавливаем начало и конец встречи;
    Instant startOfDay = meetingDateTime.atZone(ZoneId.of("UTC")).toLocalDate().atStartOfDay(ZoneId.of("UTC")).toInstant(); // Начало дня в UTC
    if (timezoneOffset != null) {
      startOfDay = startOfDay.plusSeconds(timezoneOffset * 60);
    }
    Instant endOfDay = startOfDay.plusSeconds(86400); // Конец дня (86400 секунд = 1 день)
    if (timezoneOffset != null) {
      endOfDay = endOfDay.plusSeconds(timezoneOffset * 60);
    }

    return this.meetingRepository.findByLocationWithinBoundsAndDateTime(
      upperLeftLongitude,
      lowerRightLatitude,
      lowerRightLongitude,
      upperLeftLatitude,
      startOfDay,
      endOfDay
    );
  }
}
